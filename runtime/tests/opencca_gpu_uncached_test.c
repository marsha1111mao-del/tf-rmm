/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual PT/lifetime core; CPU attributes, caches and AS are models only. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "opencca_gpu_private.c"

#define PAGE 4096UL
#define IPA 0x100000UL
#define PA 0x60100000UL
#define VA 0x200000UL
#define PAGES 514U
enum visibility { WB, HIDDEN, NC };
static enum visibility visibility[PAGES];
static unsigned char contents[PAGES];
static int client, service, other;
static unsigned int hides, syncs, nc_restores, clears, wb_restores, barriers, returns;
static unsigned int fail_hide, fail_sync, fail_nc, fail_clear, fail_wb, fail_barrier;
static bool ordinary;
static unsigned int index_of(unsigned long pa)
{
    assert(pa >= PA && pa < PA + PAGES * PAGE && !(pa & 4095UL));
    return (unsigned int)((pa - PA) / PAGE);
}
static bool source(const void *owner, unsigned long ipa, unsigned long *pa)
{
    if (owner != &client || ipa < IPA || ipa >= IPA + PAGES * PAGE ||
        gpu_private_range_busy(owner, ipa, PAGE)) return false;
    unsigned int i = (unsigned int)((ipa - IPA) / PAGE);
    assert(visibility[i] == WB); *pa = PA + i * PAGE; return true;
}
static bool hide(const void *owner, unsigned long ipa, unsigned long pa)
{
    unsigned int i = index_of(pa);
    assert(owner == &client && ipa == IPA + i * PAGE && visibility[i] != HIDDEN);
    assert(gpu_private_range_busy(owner, ipa, PAGE));
    if (++hides == fail_hide) return false;
    visibility[i] = HIDDEN; return true;
}
static bool sync_device(unsigned long pa)
{
    unsigned int i = index_of(pa);
    assert(visibility[i] == HIDDEN || (ordinary && i == PAGES-1 && visibility[i] == WB));
    return ++syncs != fail_sync;
}
static bool restore_nc(const void *owner, unsigned long ipa, unsigned long pa)
{
    unsigned int i = index_of(pa);
    assert(owner == &client && ipa == IPA + i * PAGE && visibility[i] == HIDDEN);
    assert(syncs >= nc_restores + 1U);
    if (++nc_restores == fail_nc) return false;
    visibility[i] = NC; return true;
}
static bool clear(unsigned long pa)
{
    unsigned int i = index_of(pa); assert(visibility[i] == HIDDEN);
    if (++clears == fail_clear) return false;
    contents[i] = 0; return true;
}
static bool restore_wb(const void *owner, unsigned long ipa, unsigned long pa)
{
    unsigned int i = index_of(pa);
    assert(owner == &client && ipa == IPA + i * PAGE && visibility[i] == HIDDEN && !contents[i]);
    if (++wb_restores == fail_wb) return false;
    visibility[i] = WB; return true;
}
static bool barrier(void) { return ++barriers != fail_barrier; }
static bool sync_cpu(unsigned long pa)
{
    assert(ordinary && index_of(pa) == PAGES-1 && visibility[PAGES-1] == WB);
    returns++; return true;
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
    .source_page=source, .hide_page=hide, .restore_page=restore_wb,
    .restore_page_uncached=restore_nc, .cache_barrier=barrier, .clear_page=clear,
    .sync_page_for_device=sync_device, .sync_page_for_cpu=sync_cpu,
    .table_pa=table_pa, .clean=clean, .prepare_as=prepare, .detach_as=detach, .extend_as=extend
};
static void release(unsigned long bo)
{
    struct gpu_private_result r;unsigned int calls=0;
    do {
        gpu_private_bo_release(&ops,&client,bo,&r);
        assert(++calls<4);
    } while(r.status==GPU_PRIVATE_INCOMPLETE);
    assert(!r.status);
}
static void begin(unsigned long ctx)
{
    struct gpu_private_result r;struct gpu_private_command_range empty={0};
    assert(gpu_private_task_hold_batch(&ops,&service,&client,ctx,&empty,1));
    gpu_private_context_prepare(&ops,&service,&client,ctx,1,&r);assert(!r.status);
}
int main(int argc, char **argv)
{
    assert(argc==2);unsigned int scenario=(unsigned int)strtoul(argv[1],NULL,10);
    assert(scenario<24);
    unsigned int pages=scenario==1 || scenario==8 || scenario==22 ? 513U : scenario==19?32U:3U;
    unsigned long ipas[512],bo,ctx,wb=0;
    struct gpu_private_result r;struct gpu_private_ops use=ops;
    memset(contents,0x5a,sizeof(contents));
    gpu_private_bo_create(&client,&service,pages*PAGE,scenario==21?3:7,&r);assert(!r.status);bo=r.value[0];
    for(unsigned int first=0;first<pages;first+=512) {
        unsigned int n=pages-first;if(n>512)n=512;if(scenario==2)n--;
        for(unsigned int i=0;i<n;i++)ipas[i]=IPA+(first+i)*PAGE;
        gpu_private_bo_append(&ops,&client,bo,first*PAGE,ipas,n,&r);assert(!r.status);
    }
    gpu_private_context_create(&ops,&client,&service,&r);assert(!r.status);ctx=r.value[0];
    if(scenario==21) {
        gpu_private_bo_seal(&ops,&client,bo,&r);assert(!r.status);
        gpu_private_bo_uncached(&ops,&client,bo,&r);assert(r.status && hides==pages && syncs==pages);
        release(bo);goto done;
    }
    if(scenario==3) {
        gpu_private_map(&ops,&client,ctx,bo,0,VA,1,7|8,&r);assert(!r.status);
    }
    if(scenario==4) {
        gpu_private_map_authorize(&client,ctx,bo,0,VA,1,7|8,&r);assert(!r.status);
    }
    if(scenario==5)fail_hide=2;
    if(scenario==6 || scenario==22)fail_sync=2;
    if(scenario==7)fail_nc=2;
    if(scenario==8)fail_hide=513;
    if(scenario==14)use.restore_page_uncached=NULL;
    if(scenario==20)use.cache_barrier=NULL;
    gpu_private_bo_uncached(&use,scenario==9?&other:scenario==10?&service:&client,bo,&r);
    if((scenario>=2 && scenario<=4) || scenario==9 || scenario==10 || scenario==14 || scenario==20) {
        assert(r.status && !hides && !syncs);
        gpu_private_device_revoked(&ops);release(bo);goto done;
    }
    if(scenario==1 || scenario==8) {
        assert(r.status==GPU_PRIVATE_INCOMPLETE && r.value[0]==512 && hides==512 && syncs==512);
        gpu_private_map(&ops,&client,ctx,bo,0,VA,1,7|8,&r);assert(r.status);
        gpu_private_map_authorize(&client,ctx,bo,0,VA,1,7|8,&r);assert(r.status);
        gpu_private_bo_uncached(&ops,&client,bo,&r);
    }
    if((scenario>=5 && scenario<=8) || scenario==22) {
        assert(r.status==GPU_PRIVATE_STATE && bo_lookup(&client,bo)->closing);
        gpu_private_bo_uncached(&ops,&client,bo,&r);assert(r.status==GPU_PRIVATE_STATE);
        gpu_private_map(&ops,&client,ctx,bo,0,VA,1,7|8,&r);assert(r.status);
        if(scenario==22) {
            fail_clear=1;gpu_private_bo_release(&ops,&client,bo,&r);
            assert(r.status && visibility[1]==HIDDEN); /* untouched tail was released first */
            assert(gpu_private_range_busy(&client,IPA,2*PAGE));fail_clear=0;
        }
        release(bo);goto done;
    }
    assert(!r.status && r.value[0]==pages && syncs==pages && hides==pages);
    for(unsigned int i=0;i<pages;i++)assert(visibility[i]==NC && contents[i]==0x5a);
    gpu_private_bo_seal(&ops,&client,bo,&r);assert(r.status); /* modes cannot mix */
    gpu_private_bo_destroy(&client,bo,&r);assert(r.status && !clears && !wb_restores);
    gpu_private_bo_release(&ops,&other,bo,&r);assert(r.status && !clears);
    if(scenario==11 || scenario==12 || scenario==13) {
        if(scenario==11)fail_clear=1;
        if(scenario==12)fail_wb=1;
        if(scenario==13)fail_hide=hides+1;
        gpu_private_bo_release(&ops,&client,bo,&r);assert(r.status && gpu_private_range_busy(&client,IPA,pages*PAGE));
        assert(visibility[pages-1]==(scenario==13?NC:HIDDEN));
        fail_clear=fail_wb=fail_hide=0;release(bo);goto done;
    }
    if(scenario==16) {
        gpu_private_device_revoked(&ops);
        for(unsigned int i=0;i<pages;i++)assert(visibility[i]==NC);
        gpu_private_owner_reclaim(&ops,&client,&r);assert(!r.status);goto done;
    }
    if(scenario!=19) {
        for(unsigned int first=0;first<pages;first+=512) {
            unsigned int n=pages-first;if(n>512)n=512;
            gpu_private_map(&ops,&client,ctx,bo,first*PAGE,VA+first*PAGE,n,7|8,&r);assert(!r.status);
        }
    }
    gpu_private_bo_uncached(&ops,&client,bo,&r);assert(!r.status && hides==pages && syncs==pages);
    if(scenario==0 || scenario==23) {
        ordinary=true;gpu_private_bo_create(&client,&service,PAGE,3,&r);assert(!r.status);wb=r.value[0];
        ipas[0]=IPA+(PAGES-1)*PAGE;
        gpu_private_bo_append(&ops,&client,wb,0,ipas,1,&r);assert(!r.status);
        gpu_private_map(&ops,&client,ctx,wb,0,VA+0x400000,1,3|8,&r);assert(!r.status);
    }
    if(scenario!=19) {gpu_private_bo_release(&ops,&client,bo,&r);assert(r.status && !clears);}
    assert(gpu_private_context_hold(&service,&client,ctx));
    for(unsigned int round=0;round<2;round++) {
        unsigned int before_barriers=barriers;
        begin(ctx);
        if(scenario==15) {
            gpu_private_bo_uncached(&ops,&client,bo,&r);
            assert(!r.status && hides==pages && syncs==pages);
            gpu_private_bo_release(&ops,&client,bo,&r);assert(r.status && !clears);
        }
        if(scenario==17) {
            unsigned int t=walk(&ops,ctx_lookup(&client,ctx),VA,NULL);
            tables[t][(VA>>12)&511UL]&=~PTE_AF;
        }
        if(scenario==18)fail_barrier=barriers+1;
        do {gpu_private_task_cache(&ops,&service,&client,ctx,123+round,&r);}while(r.status==GPU_PRIVATE_INCOMPLETE);
        if(scenario==17 || scenario==18) {
            assert(r.status && ctx_lookup(&client,ctx)->quarantined);
            fail_barrier=0;gpu_private_device_revoked(&ops);release(bo);goto done;
        }
        assert(!r.status && r.value[0]==(unsigned long)ordinary);
        if(scenario==19 && !round) {
            gpu_private_task_extend(&ops,&service,&client,ctx,123,bo,VA,1,&r);
            assert(!r.status && r.value[0]==pages);
        }
        assert(barriers>before_barriers);
        for(unsigned int i=0;i<pages;i++) {assert(visibility[i]==NC);contents[i]=(unsigned char)(0x70+round);}
        gpu_private_context_quiesce(&ops,&service,&client,ctx,123+round,1,&r);assert(!r.status);
        do {gpu_private_task_return(&ops,&service,&client,ctx,123+round,&r);}while(r.status==GPU_PRIVATE_INCOMPLETE);
        assert(!r.status && r.value[0]==(unsigned long)ordinary);
        assert(syncs==pages+(ordinary?round+1:0) && returns==(ordinary?round+1:0));
        assert(gpu_private_task_retire(&service,&client,ctx,123+round));
        for(unsigned int i=0;i<pages;i++)assert(visibility[i]==NC && contents[i]==0x70+round);
        if(scenario==23 && !round) {
            gpu_private_unmap_bo(&ops,&client,ctx,bo,0,VA,pages,&r);assert(!r.status);
            gpu_private_map(&ops,&client,ctx,bo,0,VA,pages,7|8,&r);assert(!r.status);
            assert(hides==pages && nc_restores==pages); /* mapping reuse retains NC */
        }
    }
    gpu_private_context_put(&client,ctx);gpu_private_device_revoked(&ops);
    if(wb){gpu_private_bo_destroy(&client,wb,&r);assert(!r.status);}
    release(bo);
done:
    if(ctx_lookup(&client,ctx)) {gpu_private_context_destroy(&ops,&client,ctx,&r);assert(!r.status);}
    for(unsigned int i=0;i<pages;i++)assert(visibility[i]==WB);
    assert(!gpu_private_owner_busy(&client));
    printf("GPU_PRIVATE_UNCACHED=PASS scenario=%u; actual PT core, modeled CPU attributes/cache/AS only\n",scenario);
    return 0;
}
