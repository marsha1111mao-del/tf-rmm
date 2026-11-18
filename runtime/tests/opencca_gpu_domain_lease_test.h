/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual RSI, memory core, firmware core and platform; only hardware/REC doubles. */
#include <stdlib.h>
static void task_domain_lease_backend(unsigned long context, unsigned long group,
        unsigned long token, unsigned int client)
{
    unsigned int test = (unsigned int)strtoul(getenv("GPU_LEASE_CASE"), NULL, 10);
    const void *owner = client == 0U ? (void *)&client_a : (void *)&client_b;
    const void *other = client == 0U ? (void *)&client_b : (void *)&client_a;
    unsigned long channel = client == 0U ? 7UL : 8UL;
    struct gpu_private_result r;
    struct gpu_firmware_task_command command = {.start=0x100000UL,.bytes=64U,.queue=1U};
    unsigned int kept=0U, yielded=0U, hits=0U, misses=0U;
    bool expect_permission=false;
    assert(test <= 24U);
    domain_active=true;
    for (unsigned int cycle=0U; cycle<384U; cycle++) {
        domain_rsi_call(owner,GPU_PRIVATE_TASK_FINISH,token,7,0,0,0,0,&r);
        assert(r.status==GPU_PRIVATE_SUCCESS && r.value[0]==1UL);
        bool live=(model_groups[launch_csg].input[0]&7U)!=2U;
        kept+=live;yielded+=!live;
        expect_permission &= live;
        unsigned int before=writes, controls=control_writes;
        domain_rsi_call(owner,GPU_PRIVATE_TASK_DISPATCH_LIVE,token,7,1,0,0,0,&r);
        assert(r.status==GPU_PRIVATE_INPUT && writes==before && control_writes==controls);
        if(test==9U && cycle==1U) {
            gpu_firmware_context_yield(&fw_ops,&donated_ops,owner,context,&r);
            assert(r.status==GPU_PRIVATE_SUCCESS);expect_permission=false;
        }
        domain_rsi_call(owner,GPU_PRIVATE_TASK_STAGE_BATCH,group,
            (unsigned long)(uintptr_t)&command,7,1,
            GPU_PRIVATE_TASK_DEFERRED|GPU_PRIVATE_TASK_DELEGATE|GPU_PRIVATE_TASK_MAPPING_VERSION,0,&r);
        assert(r.status==GPU_PRIVATE_SUCCESS && r.value[3]!=0UL);
        unsigned long next=r.value[0],version=r.value[3];
        if(test==5U && cycle==1U) {
            domain_rsi_call(owner,GPU_PRIVATE_TASK_CANCEL,next,0,0,0,0,0,&r);
            assert(r.status==GPU_PRIVATE_SUCCESS);
            domain_rsi_call(owner,GPU_PRIVATE_TASK_STAGE_BATCH,group,
                (unsigned long)(uintptr_t)&command,7,1,
                GPU_PRIVATE_TASK_DEFERRED|GPU_PRIVATE_TASK_DELEGATE|GPU_PRIVATE_TASK_MAPPING_VERSION,0,&r);
            assert(r.status==GPU_PRIVATE_SUCCESS && r.value[0]!=next);
            next=r.value[0];version=r.value[3];
        }
        before=writes;controls=control_writes;
        if(test==1U && cycle==1U) {
            domain_rsi_call(other,GPU_PRIVATE_TASK_DISPATCH_LIVE,next,7,version,0,0,0,&r);
            assert(r.status==GPU_PRIVATE_INPUT);
            domain_rsi_call(&service,GPU_PRIVATE_TASK_DISPATCH_LIVE,next,channel,version,0,0,0,&r);
            assert(r.status==GPU_PRIVATE_INPUT);
            domain_rsi_call(owner,GPU_PRIVATE_TASK_DISPATCH_LEASE,next,7,context,group,version,0,&r);
            assert(r.status==GPU_PRIVATE_INPUT);
            domain_rsi_call(owner,GPU_PRIVATE_TASK_DISPATCH_LIVE,next,99,version,0,0,0,&r);
            assert(r.status==GPU_PRIVATE_INPUT);
            domain_disconnected=true;
            domain_rsi_call(owner,GPU_PRIVATE_TASK_DISPATCH_LIVE,next,7,version,0,0,0,&r);
            assert(r.status==GPU_PRIVATE_INPUT);domain_disconnected=false;
            for(unsigned int reserved=0U;reserved<3U;reserved++) {
                domain_rsi_call(owner,GPU_PRIVATE_TASK_DISPATCH_LIVE,next,7,version,
                    reserved==0U,reserved==1U,reserved==2U,&r);
                assert(r.status==GPU_PRIVATE_INPUT);
            }
            assert(writes==before && control_writes==controls);
        }
        if(test==2U && cycle==1U) {
            domain_rsi_call(owner,GPU_PRIVATE_TASK_DISPATCH_LIVE,next,7,version+1,0,0,0,&r);
            assert(r.status==GPU_PRIVATE_INPUT);
            domain_rsi_call(owner,GPU_PRIVATE_TASK_DISPATCH_LIVE,next,7,0,0,0,0,&r);
            assert(r.status==GPU_PRIVATE_INPUT && writes==before && control_writes==controls);
        }
        if(cycle==1U && test>=16U) {
            unsigned int as=model_groups[launch_csg].input[20];
            unsigned long correct_root=words64(registers+(0x2400U+as*0x40U)/4U,0U);
            uint64_t ring_va=words64(model_groups[launch_csg].cs_input[1],4U);
            uint64_t *insert=(void *)(uintptr_t)complete_read_pa[0];
            uint64_t off=insert[0]&(model_groups[launch_csg].cs_input[1][6]-1U);
            domain_prepare_destinations[0]=
                (software_leaf(correct_root,ring_va+off)&UINT64_C(0x000000fffffff000))+off%4096U;
            domain_prepare_writes=0U;
            domain_prepare_writing=true;
        }
        if(cycle==1U) {
            if(test==6U)fail_control_write=control_writes+1U;
            if(test==7U)domain_write_fault=1U; /* Root changes after protected ring write. */
            if(test==8U)gpu_private_task_clear_drained(&service,owner,context,token);
            if(test>=10U && test<=15U)domain_ready_barrier_fault=test;
            if(test>=16U && test<=21U) {
                domain_read_fault=1U+(test-16U)%3U;
                /* 16..18 fault after the post-ring snapshot; 19..21 fault
                 * after the first snapshot, wherever that occurs. This
                 * locates the event without assuming two observations. */
                domain_reads_until_fault=3U;
                domain_read_wait_for_ring=test<=18U;
            }
            if(test>=22U) {
                unsigned int as=model_groups[launch_csg].input[20];
                drain_fault=test==22U?&registers[(0x2400U+as*0x40U)/4U]:
                    test==23U?&registers[0x2400U/4U]:&model_glb_out[4];
                drain_fault_saved=*drain_fault;*drain_fault^=0x1000U;
            }
        }
        uint64_t *producer=(void *)(uintptr_t)complete_read_pa[0];
        uint64_t previous_insert=producer[0];
        unsigned int previous_mmio=mmio_reads;
        unsigned int previous_barriers=domain_ready_barriers;
        domain_rsi_call(owner,GPU_PRIVATE_TASK_DISPATCH_LIVE,next,7,version,0,0,0,&r);
        domain_prepare_writing=false;
        if(test==0U && cycle==1U)
            printf("GPU_READY_DISPATCH_MMIO client=%u reads=%u\n",client,mmio_reads-previous_mmio);
        if(cycle==1U && ((test>=6U && test<=8U) || test>=10U)) {
            assert(r.status==GPU_PRIVATE_STATE && !r.value[0]);
            if(test>=16U) {
                assert(writes==before && producer[0]==previous_insert);
                assert(domain_prepare_writes<=1U && control_writes==controls+domain_prepare_writes);
                printf("GPU_UNPUBLISHED_LEASE case=%u client=%u ring_writes=%u\n",test,client,domain_prepare_writes);
            }

            if(test>=10U)assert(domain_ready_barrier_fault==0U && producer[0]==previous_insert);
            if(test<=8U || test>=16U)
                assert(domain_read_fault==0U && domain_ready_barriers==previous_barriers);
            if(drain_fault!=NULL)*drain_fault=drain_fault_saved;
            drain_fault=NULL;fail_control_write=0U;
            before=writes;controls=control_writes;
            domain_rsi_call(owner,GPU_PRIVATE_TASK_DISPATCH_LIVE,next,7,version,0,0,0,&r);
            assert(r.status==GPU_PRIVATE_STATE || r.status==GPU_PRIVATE_INPUT);
            domain_rsi_call(&service,GPU_PRIVATE_TASK_DISPATCH_LEASE,next,channel,context,group,version,0,&r);
            assert((r.status==GPU_PRIVATE_STATE || r.status==GPU_PRIVATE_INPUT) && writes==before && control_writes==controls);
            domain_rsi_call(owner,GPU_PRIVATE_TASK_CANCEL,next,0,0,0,0,0,&r);
            /* Even a pre-write rejection retains its task/cache mapping hold:
             * cancellation may fail because the anchor is quarantined. */
            assert(r.status==GPU_PRIVATE_STATE);
            gpu_firmware_group_destroy(&donated_ops,owner,group,&r);
            assert(r.status==GPU_PRIVATE_STATE);
            destroy_prepared_bo(owner,prepared_bos[client],&r);
            assert(r.status==GPU_PRIVATE_STATE);
            goto done;
        }
        assert(r.status==GPU_PRIVATE_SUCCESS);
        if(!r.value[0]) {
            assert(!expect_permission && !r.value[1] && !r.value[2] && !r.value[3]);
            assert(writes==before && control_writes==controls);misses++;
            bool legacy=test==4U && cycle==0U;
            domain_rsi_call(&service,legacy?GPU_PRIVATE_TASK_DISPATCH:GPU_PRIVATE_TASK_DISPATCH_LEASE,
                next,channel,context,group,version,0,&r);
            assert(r.status==GPU_PRIVATE_SUCCESS);expect_permission=!legacy;
        } else { assert(expect_permission);hits++; }
        assert(r.value[0]==GPU_FIRMWARE_GROUP_STARTED && r.value[1]==1UL && !r.value[2] && !r.value[3]);
        domain_bind_model();
        before=writes;controls=control_writes;
        domain_rsi_call(owner,GPU_PRIVATE_TASK_DISPATCH_LIVE,next,7,version,0,0,0,&r);
        assert(r.status==GPU_PRIVATE_STATE && writes==before && control_writes==controls);
        if(test==3U) {
            domain_rsi_call(&service,GPU_PRIVATE_TASK_DISPATCH_LEASE,next,channel,context,group,version,0,&r);
            assert(r.status==GPU_PRIVATE_STATE && writes==before && control_writes==controls);
        }
        token=next;
    }
    if(test!=9U)assert(kept==(client==0U?336U:(384U-384U/GPU_TEST_SOLO_QUANTUM)) && yielded==(client==0U?48U:(384U/GPU_TEST_SOLO_QUANTUM)));
    assert(hits>70U && misses>0U);
    /* A real staged competitor forces the next completed boundary to yield. */
    gpu_private_context_create(&donated_ops,&client_b,&service,&r);assert(r.status==GPU_PRIVATE_SUCCESS);
    unsigned long wc=r.value[0];
    gpu_firmware_group_create(&fw_ops,&donated_ops,&service,&client_b,wc,1,&r);assert(r.status==GPU_PRIVATE_SUCCESS);
    unsigned long wg=r.value[0];
    struct gpu_firmware_queue_config queue={.ring_bytes=4096U};
    gpu_firmware_group_configure(&donated_ops,&service,&client_b,wg,&queue,1,&r);assert(r.status==GPU_PRIVATE_SUCCESS);
    struct gpu_firmware_task_command empty={0};
    domain_rsi_call(&client_b,GPU_PRIVATE_TASK_STAGE_BATCH,wg,(unsigned long)(uintptr_t)&empty,7,1,GPU_PRIVATE_TASK_DEFERRED,0,&r);
    assert(r.status==GPU_PRIVATE_SUCCESS);unsigned long waiter=r.value[0];
    domain_rsi_call(owner,GPU_PRIVATE_TASK_FINISH,token,7,0,0,0,0,&r);
    assert(r.status==GPU_PRIVATE_SUCCESS && (model_groups[launch_csg].input[0]&7U)==2U);
    domain_rsi_call(&client_b,GPU_PRIVATE_TASK_CANCEL,waiter,0,0,0,0,0,&r);assert(r.status==GPU_PRIVATE_SUCCESS);
    gpu_firmware_group_destroy(&donated_ops,&client_b,wg,&r);assert(r.status==GPU_PRIVATE_SUCCESS);
    gpu_private_context_destroy(&donated_ops,&client_b,wc,&r);assert(r.status==GPU_PRIVATE_SUCCESS);
    gpu_firmware_context_yield(&fw_ops,&donated_ops,owner,context,&r);assert(r.status==GPU_PRIVATE_SUCCESS);
    gpu_firmware_group_inspect(&service,owner,group,&r);assert(r.status==GPU_PRIVATE_SUCCESS && r.value[0]==GPU_FIRMWARE_GROUP_RESERVED);
 done:
    domain_active=false;
    printf("GPU_DOMAIN_LEASE=PASS case=%u client=%u hits=%u misses=%u kept=%u yielded=%u actual_RSI_and_cores MODEL_ONLY\n",test,client,hits,misses,kept,yielded);
}
