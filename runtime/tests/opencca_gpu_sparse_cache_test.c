/* SPDX-License-Identifier: BSD-3-Clause */
/* Real PT/cache core with synthetic ownership/AS callbacks. No hardware. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "opencca_gpu_private.c"

#define PAGE 4096UL
#define VA 0x200000UL
#define TOKEN 123UL
static int client, other, service;
static unsigned long next_ipa = 0x100000UL;
static unsigned long expected[1024];
static unsigned int expected_count, device_count, cpu_count, device_calls, cpu_calls;
static bool fail_sync;
static unsigned long table_pa(const void *p)
{ return 0x100000000UL + (const unsigned char *)p - (const unsigned char *)tables; }
static void clean(const void *p, size_t bytes) { assert(p && bytes); }
static bool source(const void *owner, unsigned long ipa, unsigned long *pa)
{
    assert(owner == &client || owner == &other);
    *pa = ipa + (owner == &client ? 0x40000000UL : 0x80000000UL);
    return !gpu_private_range_busy(owner, ipa, PAGE);
}
static bool prepare(unsigned long root, unsigned int slot, unsigned long fw, bool existing)
{ (void)existing; assert(root && slot && fw); return true; }
static bool detach(unsigned long root, unsigned int slot, unsigned long fw, bool detached)
{ (void)detached; assert(root && slot && fw); return true; }
static bool sync_device(unsigned long pa)
{
    assert(device_count < expected_count && expected[device_count] == pa);
    device_count++; return !fail_sync;
}
static bool sync_cpu(unsigned long pa)
{
    assert(cpu_count < expected_count && expected[cpu_count] == pa);
    cpu_count++; return true;
}
static const struct gpu_private_ops ops = {
    .source_page=source, .table_pa=table_pa, .clean=clean, .prepare_as=prepare,
    .detach_as=detach, .sync_page_for_device=sync_device, .sync_page_for_cpu=sync_cpu
};
static unsigned long make_bo(const void *owner, unsigned int pages)
{
    struct gpu_private_result r; unsigned long ipas[512];
    gpu_private_bo_create(owner,&service,pages*PAGE,3,&r);assert(!r.status);
    unsigned long bo=r.value[0];
    for(unsigned int first=0;first<pages;first+=512) {
        unsigned int n=pages-first;if(n>512)n=512;
        for(unsigned int i=0;i<n;i++){ipas[i]=next_ipa;next_ipa+=PAGE;}
        gpu_private_bo_append(&ops,owner,bo,first*PAGE,ipas,n,&r);assert(!r.status);
    }
    return bo;
}
static unsigned long make_context(const void *owner)
{
    struct gpu_private_result r;
    gpu_private_context_create(&ops,owner,&service,&r);assert(!r.status);return r.value[0];
}
static void map(const void *owner,unsigned long ctx,unsigned long bo,unsigned int offset,
                unsigned long va,unsigned int count)
{
    struct gpu_private_result r;
    gpu_private_map(&ops,owner,ctx,bo,offset*PAGE,va,count,3|8,&r);assert(!r.status);
}
static void expect(const void *owner,unsigned long bo,unsigned int first,unsigned int count)
{
    struct private_bo *b=bo_lookup(owner,bo);assert(b);
    for(unsigned int i=0;i<count;i++)expected[expected_count++]=(unsigned long)bo_page(b,first+i)->pa_page<<12;
}
static void begin(const void *owner,unsigned long ctx)
{
    struct gpu_private_result r;struct gpu_private_command_range empty={0};
    assert(gpu_private_context_hold(&service,owner,ctx));
    assert(gpu_private_task_hold_batch(&ops,&service,owner,ctx,&empty,1));
    gpu_private_context_prepare(&ops,&service,owner,ctx,1,&r);assert(!r.status);
}
static void exercise(const void *owner,unsigned long ctx)
{
    struct gpu_private_result r;
    device_count=cpu_count=device_calls=cpu_calls=0;
    begin(owner,ctx);
    do {
        unsigned int before=device_count;
        gpu_private_task_cache(&ops,&service,owner,ctx,TOKEN,&r);
        assert(device_count-before<=512 && ++device_calls<100);
    } while(r.status==GPU_PRIVATE_INCOMPLETE);
    assert(!r.status && r.value[0]==expected_count && device_count==expected_count);
    gpu_private_context_quiesce(&ops,&service,owner,ctx,TOKEN,1,&r);assert(!r.status);
    do {
        unsigned int before=cpu_count;
        gpu_private_task_return(&ops,&service,owner,ctx,TOKEN,&r);
        assert(cpu_count-before<=512 && ++cpu_calls<100);
    } while(r.status==GPU_PRIVATE_INCOMPLETE);
    assert(!r.status && r.value[0]==expected_count && cpu_count==expected_count);
    assert(gpu_private_task_retire(&service,owner,ctx,TOKEN));
    gpu_private_context_put(owner,ctx);
}
int main(int argc,char **argv)
{
    assert(argc==2);unsigned int scenario=(unsigned int)strtoul(argv[1],NULL,10);assert(scenario<6);
    struct gpu_private_result r;unsigned long ctx=make_context(&client);
    unsigned long bo=make_bo(&client,scenario==1?513:16);
    if(scenario==0) {
        /* Every group boundary and sparse 2-MiB tables. Check all actual PAs. */
        unsigned int slots[]={0,31,32,63,64,255,256,479,480,511};
        for(unsigned int i=0;i<10;i++){map(&client,ctx,bo,i,VA+slots[i]*PAGE,1);expect(&client,bo,i,1);}
        for(unsigned int i=10;i<16;i++){map(&client,ctx,bo,i,VA+(i-9)*0x200000UL+511*PAGE,1);expect(&client,bo,i,1);}
        exercise(&client,ctx);assert(device_calls<=2 && cpu_calls<=2);
    } else if(scenario==1) {
        map(&client,ctx,bo,0,VA,512);map(&client,ctx,bo,512,VA+512*PAGE,1);
        expect(&client,bo,0,513);exercise(&client,ctx);assert(device_calls>=2 && cpu_calls>=2);
    } else if(scenario==2) {
        /* Clearing a neighbor must not hide a surviving mapping. Test both removers. */
        map(&client,ctx,bo,0,VA,2);map(&client,ctx,bo,2,VA+511*PAGE,1);
        gpu_private_unmap(&ops,&client,ctx,VA,1,&r);assert(!r.status);
        expect(&client,bo,1,2);exercise(&client,ctx);
        gpu_private_unmap_bo(&ops,&client,ctx,bo,PAGE,VA+PAGE,1,&r);assert(!r.status);
        gpu_private_unmap_bo(&ops,&client,ctx,bo,2*PAGE,VA+511*PAGE,1,&r);assert(!r.status);
        expected_count=0;exercise(&client,ctx);assert(device_calls==1 && cpu_calls==1);
        map(&client,ctx,bo,5,VA+511*PAGE,1);expect(&client,bo,5,1);exercise(&client,ctx);
    } else if(scenario==3) {
        /* Unrelated Client leaves must never enter this cache transaction. */
        unsigned long ctx2=make_context(&other),bo2=make_bo(&other,1);
        map(&other,ctx2,bo2,0,VA,1);map(&client,ctx,bo,0,VA+511*PAGE,1);
        expect(&client,bo,0,1);exercise(&client,ctx);
        gpu_private_device_revoked(&ops);
        gpu_private_context_destroy(&ops,&client,ctx,&r);assert(!r.status);
        gpu_private_context_destroy(&ops,&other,ctx2,&r);assert(!r.status);
        gpu_private_bo_destroy(&other,bo2,&r);assert(!r.status);
        ctx=make_context(&client);expected_count=0;
        map(&client,ctx,bo,3,VA+32*PAGE,1);expect(&client,bo,3,1);exercise(&client,ctx);
    } else {
        map(&client,ctx,bo,0,VA+511*PAGE,1);expect(&client,bo,0,1);
        if(scenario==4) {
            unsigned int table=walk(&ops,ctx_lookup(&client,ctx),VA+511*PAGE,NULL);
            tables[table][511]&=~PTE_AF; /* Occupied leaf still checks real PTE. */
        } else fail_sync=true;
        begin(&client,ctx);
        do {gpu_private_task_cache(&ops,&service,&client,ctx,TOKEN,&r);}while(r.status==GPU_PRIVATE_INCOMPLETE);
        assert(r.status==GPU_PRIVATE_STATE && ctx_lookup(&client,ctx)->quarantined);
        assert(device_count==(scenario==5));
        assert(!gpu_private_task_retire(&service,&client,ctx,TOKEN));
        gpu_private_bo_destroy(&client,bo,&r);assert(r.status);
    }
    gpu_private_device_revoked(&ops);
    do {gpu_private_bo_destroy(&client,bo,&r);}while(r.status==GPU_PRIVATE_INCOMPLETE);
    assert(!r.status);
    gpu_private_context_destroy(&ops,&client,ctx,&r);assert(!r.status);
    for(unsigned int i=0;i<GPU_PRIVATE_TABLES;i++)assert(!leaf_groups[i]);
    assert(!gpu_private_owner_busy(&client) && !gpu_private_owner_busy(&other));
    printf("GPU_PRIVATE_SPARSE_CACHE=PASS scenario=%u device_calls=%u return_calls=%u; models only\n",scenario,device_calls,cpu_calls);
    return 0;
}
