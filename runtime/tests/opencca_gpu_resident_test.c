/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual PT core, modeled CPU visibility/cache/AS operations. No hardware. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "opencca_gpu_private.c"

#define PAGE 4096UL
#define IPA 0x100000UL
#define PA 0x60100000UL
#define VA 0x200000UL
#define MAX_PAGES 513U
static int client, other, service;
static bool visible[MAX_PAGES];
static unsigned char contents[MAX_PAGES];
static unsigned int hides, syncs, returns, clears, restores;
static unsigned int fail_hide, fail_sync, fail_clear, fail_restore;
static bool mixed;
static unsigned int index_of(unsigned long pa)
{
    assert(pa >= PA && pa < PA + MAX_PAGES * PAGE && !(pa & 4095UL));
    return (unsigned int)((pa - PA) / PAGE);
}
static bool source(const void *owner, unsigned long ipa, unsigned long *pa)
{
    if (owner != &client || ipa < IPA || ipa >= IPA + MAX_PAGES * PAGE ||
        gpu_private_range_busy(owner, ipa, PAGE)) return false;
    unsigned int i = (unsigned int)((ipa - IPA) / PAGE);
    if (!visible[i]) return false;
    *pa = PA + i * PAGE; return true;
}
static bool hide(const void *owner, unsigned long ipa, unsigned long pa)
{
    unsigned int i = index_of(pa);
    assert(owner == &client && ipa == IPA + i * PAGE && visible[i]);
    assert(gpu_private_range_busy(owner, ipa, PAGE));
    if (++hides == fail_hide) return false;
    visible[i] = false; return true;
}
static bool sync_device(unsigned long pa)
{
    assert(!visible[index_of(pa)] || (mixed && index_of(pa)==MAX_PAGES-1)); /* Ordinary data retains CPU mappings. */
    return ++syncs != fail_sync;
}
static bool sync_cpu(unsigned long pa) { (void)pa; returns++; return true; }
static bool clear(unsigned long pa)
{
    unsigned int i = index_of(pa); assert(!visible[i]);
    if (++clears == fail_clear) return false;
    contents[i] = 0; return true;
}
static bool restore(const void *owner, unsigned long ipa, unsigned long pa)
{
    unsigned int i = index_of(pa);
    assert(owner == &client && ipa == IPA + i * PAGE && !visible[i] && !contents[i]);
    if (++restores == fail_restore) return false;
    visible[i] = true; return true;
}
static unsigned long table_pa(const void *p)
{ return 0x100000000UL + (const unsigned char *)p - (const unsigned char *)tables; }
static void clean(const void *p, size_t bytes) { assert(p && bytes); }
static bool prepare(unsigned long root, unsigned int slot, unsigned long fw, bool existing)
{ (void)existing; assert(root && slot && fw); return true; }
static bool detach(unsigned long root, unsigned int slot, unsigned long fw, bool detached)
{ (void)detached; assert(root && slot && fw); return true; }
static bool extend(unsigned long root, unsigned int slot, unsigned long fw)
{ assert(root && slot && fw); return true; }
static const struct gpu_private_ops ops = {
    .source_page=source, .hide_page=hide, .restore_page=restore, .clear_page=clear,
    .sync_page_for_device=sync_device, .sync_page_for_cpu=sync_cpu,
    .table_pa=table_pa, .clean=clean, .prepare_as=prepare, .detach_as=detach, .extend_as=extend
};
static void release(unsigned long bo)
{
    struct gpu_private_result r;
    do { gpu_private_bo_release(&ops,&client,bo,&r); } while(r.status==GPU_PRIVATE_INCOMPLETE);
    assert(!r.status && !gpu_private_range_busy(&client,IPA,MAX_PAGES*PAGE));
}
int main(int argc, char **argv)
{
    assert(argc==2); unsigned int scenario=(unsigned int)strtoul(argv[1],NULL,10);
    assert(scenario<19);
    unsigned int pages=scenario==1 || scenario==8 ? MAX_PAGES : scenario==18?32U:3U;
    unsigned long ipas[512],bo,ctx,ordinary=0;
    struct gpu_private_result r;
    memset(visible,true,sizeof(visible));memset(contents,0x5a,sizeof(contents));
    gpu_private_bo_create(&client,&service,pages*PAGE,scenario==2?7UL:3UL,&r);assert(!r.status);bo=r.value[0];
    for(unsigned int first=0;first<pages;first+=512) {
        unsigned int n=pages-first; if(n>512)n=512;
        if(scenario==3) n--;
        for(unsigned int i=0;i<n;i++)ipas[i]=IPA+(first+i)*PAGE;
        gpu_private_bo_append(&ops,&client,bo,first*PAGE,ipas,n,&r);assert(!r.status);
    }
    gpu_private_context_create(&ops,&client,&service,&r);assert(!r.status);ctx=r.value[0];
    if(scenario==4 || scenario==5) {
        if(scenario==4)gpu_private_map(&ops,&client,ctx,bo,0,VA,1,3|8,&r);
        else gpu_private_map_authorize(&client,ctx,bo,0,VA,1,3|8,&r);
        assert(!r.status);
    }
    if(scenario==6)fail_hide=2;
    if(scenario==7)fail_sync=2;
    if(scenario==8)fail_hide=513;
    const void *caller=scenario==9?&other:scenario==10?&service:&client;
    struct gpu_private_ops use=ops;
    if(scenario==15)use.hide_page=NULL;
    if(scenario==16)use.sync_page_for_device=NULL;
    gpu_private_bo_seal(&use,caller,scenario==17?bo+0x10000:bo,&r);
    if((scenario>=2 && scenario<=5) || scenario==9 || scenario==10 || (scenario>=15 && scenario<=17)) {
        assert(r.status && !hides && !syncs);
        gpu_private_device_revoked(&ops);
        release(bo); goto done;
    }
    if(scenario==1 || scenario==8) {
        assert(r.status==GPU_PRIVATE_INCOMPLETE && r.value[0]==512 && hides==512 && syncs==512);
        gpu_private_map(&ops,&client,ctx,bo,0,VA,1,3|8,&r);assert(r.status);
        gpu_private_bo_seal(&ops,&client,bo,&r);
    }
    if(scenario>=6 && scenario<=8) {
        assert(r.status==GPU_PRIVATE_STATE && bo_lookup(&client,bo)->closing);
        gpu_private_bo_seal(&ops,&client,bo,&r);assert(r.status==GPU_PRIVATE_STATE);
        gpu_private_map(&ops,&client,ctx,bo,0,VA,1,3|8,&r);assert(r.status);
        release(bo);
        for(unsigned int i=0;i<pages;i++)assert(visible[i]);
        goto done;
    }
    assert(!r.status && r.value[0]==pages && syncs==pages && hides==pages);
    for(unsigned int i=0;i<pages;i++)assert(!visible[i] && contents[i]==0x5a);
    gpu_private_bo_destroy(&client,bo,&r);assert(r.status && !clears && !restores);
    gpu_private_bo_release(&ops,&other,bo,&r);assert(r.status && !clears);
    if(scenario==11)fail_clear=1;
    if(scenario==12)fail_restore=1;
    if(scenario==11 || scenario==12) {
        gpu_private_bo_release(&ops,&client,bo,&r);assert(r.status && gpu_private_range_busy(&client,IPA,pages*PAGE));
        for(unsigned int i=0;i<pages;i++)assert(!visible[i]);
        fail_clear=fail_restore=0;release(bo);goto done;
    }
    if(scenario==13) {
        gpu_private_map_authorize(&client,ctx,bo,0,VA,1,3|8,&r);assert(!r.status);
        gpu_private_bo_release(&ops,&client,bo,&r);assert(r.status && !clears);
        gpu_private_device_revoked(&ops);release(bo);goto done;
    }
    if(scenario==14) {
        gpu_private_device_revoked(&ops);
        for(unsigned int i=0;i<pages;i++)assert(!visible[i]);
        gpu_private_owner_reclaim(&ops,&client,&r);assert(!r.status);goto done;
    }
    if(scenario==18) {
        struct gpu_private_command_range empty={0};
        assert(gpu_private_context_hold(&service,&client,ctx));
        assert(gpu_private_task_hold_batch(&ops,&service,&client,ctx,&empty,1));
        gpu_private_context_prepare(&ops,&service,&client,ctx,1,&r);assert(!r.status);
        do {gpu_private_task_cache(&ops,&service,&client,ctx,123,&r);}while(r.status==GPU_PRIVATE_INCOMPLETE);
        assert(!r.status);
        gpu_private_task_extend(&ops,&service,&client,ctx,123,bo,VA,1,&r);
        assert(!r.status && r.value[0]==pages && syncs==pages);
        gpu_private_context_quiesce(&ops,&service,&client,ctx,123,1,&r);assert(!r.status);
        do {gpu_private_task_return(&ops,&service,&client,ctx,123,&r);}while(r.status==GPU_PRIVATE_INCOMPLETE);
        assert(!r.status && !r.value[0] && !returns);
        assert(gpu_private_task_retire(&service,&client,ctx,123));
        gpu_private_device_revoked(&ops);release(bo);goto done;
    }
    for(unsigned int first=0;first<pages;first+=512) {
        unsigned int n=pages-first;if(n>512)n=512;
        gpu_private_map(&ops,&client,ctx,bo,first*PAGE,VA+first*PAGE,n,3|8,&r);assert(!r.status);
    }
    if(scenario==0) {
        mixed=true;gpu_private_bo_create(&client,&service,PAGE,3,&r);assert(!r.status);ordinary=r.value[0];
        ipas[0]=IPA+(MAX_PAGES-1)*PAGE;
        gpu_private_bo_append(&ops,&client,ordinary,0,ipas,1,&r);assert(!r.status);
        gpu_private_map(&ops,&client,ctx,ordinary,0,VA+(pages+1)*PAGE,1,3|8,&r);assert(!r.status);
    }
    gpu_private_bo_seal(&ops,&client,bo,&r);assert(!r.status && hides==pages && syncs==pages);
    gpu_private_bo_release(&ops,&client,bo,&r);assert(r.status && !clears);
    assert(gpu_private_context_hold(&service,&client,ctx));
    struct gpu_private_command_range empty={0};
    for(unsigned int round=0;round<2;round++) {
        assert(gpu_private_task_hold_batch(&ops,&service,&client,ctx,&empty,1));
        gpu_private_context_prepare(&ops,&service,&client,ctx,1,&r);assert(!r.status);
        do {gpu_private_task_cache(&ops,&service,&client,ctx,123+round,&r);}while(r.status==GPU_PRIVATE_INCOMPLETE);
        assert(!r.status && r.value[0]==(unsigned long)mixed && syncs==pages+(mixed?round+1:0));
        gpu_private_context_quiesce(&ops,&service,&client,ctx,123+round,1,&r);assert(!r.status);
        do {gpu_private_task_return(&ops,&service,&client,ctx,123+round,&r);}while(r.status==GPU_PRIVATE_INCOMPLETE);
        assert(!r.status && r.value[0]==(unsigned long)mixed && returns==(mixed?round+1:0) && !clears);
        assert(gpu_private_task_retire(&service,&client,ctx,123+round));
        for(unsigned int i=0;i<pages;i++)assert(!visible[i]);
    }
    gpu_private_context_put(&client,ctx);
    gpu_private_device_revoked(&ops);
    if(ordinary){gpu_private_bo_destroy(&client,ordinary,&r);assert(!r.status);}
    release(bo);
    for(unsigned int i=0;i<pages;i++)assert(visible[i] && !contents[i]);
done:
    if(ctx_lookup(&client,ctx)) {
        gpu_private_context_destroy(&ops,&client,ctx,&r);assert(!r.status);
    }
    assert(!gpu_private_owner_busy(&client));
    printf("GPU_PRIVATE_RESIDENT=PASS scenario=%u; actual PT core, CPU visibility/cache/AS models only\n",scenario);
    return 0;
}
