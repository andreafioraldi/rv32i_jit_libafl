use std::{env, path::PathBuf};

use libafl::{
    bolts::{
        current_nanos,
        launcher::Launcher,
        os::Cores,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
        AsSlice,
    },
    corpus::{InMemoryCorpus, OnDiskCorpus, RandCorpusScheduler},
    events::EventConfig,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, ListFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::tui::TuiMonitor,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::ListObserver,
    stages::mutational::StdMutationalStage,
    state::StdState,
    Error,
};

use vm::x86asm::AsmStream;
use vm::{Register, Vm, VmExit};

// VM properties we're going to use
const BASE: u32 = 0x10000;
const SIZE: usize = 512 * 1024;
const INSTS: usize = SIZE / 4;
const STACKSZ: u32 = 128 * 1024;
const HEAPSZ: u32 = 32 * 1024;
const DIRTY: usize = SIZE / (256 * 8);

/// Re-type a VM with our specific properties
type OurVm = Vm<AsmStream<BASE, SIZE, INSTS, DIRTY>, BASE, SIZE, INSTS, STACKSZ, HEAPSZ, DIRTY>;

/// New coverage seen
static mut COVERAGE: Vec<u32> = vec![];
fn add_coverage(pc: u32) {
    unsafe { COVERAGE.push(pc) };
}

pub fn main() {
    let mut orig_vm =
        OurVm::from_felf("../example_snapshot_fuzzer/test_app/x509-parser.felf", &["x509-parser", "example.der"])
            .expect("Loading failed");
    orig_vm.jit().expect("JIT failed");

    // Run the original VM until it hits the fuzz case start syscall
    let (fuzz_input, fuzz_input_len) = loop {
        match orig_vm.run() {
            VmExit::Coverage => {}
            VmExit::Ecall => {
                let id = orig_vm.reg(Register::A7) as i32;
                assert!(id == 103);
                break (orig_vm.reg(Register::A0), orig_vm.reg(Register::A1));
            }
            x @ _ => panic!("Unexpected vmexit {:?}", x),
        }
    };

    let mut vm = orig_vm.clone();

    let mut run_client = |state: Option<StdState<_, _, _, _, _>>, mut mgr, _core_id| {
        let mut harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();

            // Reset VM state to the state of `orig_vm`
            vm.reset_to(&orig_vm);

            // Write in the input
            vm.write_u16(fuzz_input_len, buf.len() as u16).unwrap();
            vm.write(fuzz_input, &buf).unwrap();

            // Loop while handling vmexits
            let mut execute = true;
            while execute {
                // Execute the VM!
                let exit = vm.run();

                // Handle vmexits
                match exit {
                    VmExit::Coverage => {
                        // Record coverage
                        let pc = vm.reg(Register::PC);
                        add_coverage(pc);
                    }
                    VmExit::Ecall => {
                        // Syscall
                        let number = vm.reg(Register::A7);

                        match number {
                            100 => {
                                // Write byte in A0
                                let byte = vm.reg(Register::A0) as u8;
                                //print!("{}", byte as char);
                            }
                            101 => {
                                // Exit
                                let code = vm.reg(Register::A0) as i32;
                                //println!("Exited with: {}", code);

                                // Stop execution
                                execute = false;
                            }
                            102 => {
                                // Sbrk
                                let ret = vm.sbrk(vm.reg(Register::A0) as i32);
                                if let Some(ret) = ret {
                                    vm.set_reg(Register::A0, ret);
                                } else {
                                    // Failed to allocate
                                    vm.set_reg(Register::A0, !0);
                                }
                            }
                            _ => {
                                eprintln!("Unhandled syscall {}", number);
                                return ExitKind::Crash;
                            }
                        }
                    }
                    _ => {
                        vm.dump_regs();
                        eprintln!("Unhandled vmexit {:x?}", exit);
                        return ExitKind::Crash;
                    }
                }
            }

            ExitKind::Ok
        };

        let observer = ListObserver::new("cov", unsafe { &mut COVERAGE });
        let feedback = ListFeedback::new_with_observer(&observer);

        let objective = CrashFeedback::new();

        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                StdRand::with_seed(current_nanos()),
                InMemoryCorpus::new(),
                OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
                (),
            )
        });

        let scheduler = RandCorpusScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .expect("Failed to create the Executor");

        let mut generator = RandPrintablesGenerator::new(32);
        // Generate 8 initial inputs
        state
            .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
            .expect("Failed to generate the initial corpus");

        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");

        Ok(())
    };

    let port = portpicker::pick_unused_port().expect("No ports free");
    println!("Picking the free port {}", port);

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    let monitor = TuiMonitor::new("rv32i_jit + libafl fuzzer".into(), true);

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        // pin to the first core only one instance of the fuzzer if not specified
        .cores(&Cores::from_cmdline(&env::args().nth(1).unwrap_or("0".into())).unwrap())
        .broker_port(port)
        .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    }
}
