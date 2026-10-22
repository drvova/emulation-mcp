use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use icicle_cpu::mem::{Mapping, MemError, perm};
use icicle_cpu::{Cpu, ExceptionCode, ValueSource, VmExit};
use pyo3::prelude::*;
use pyo3::exceptions::*;
use indexmap::IndexMap;
use target_lexicon::Architecture;
use sleigh_runtime::NamedRegister;

// References:
// - https://pyo3.rs/main/conversions/tables
// - https://pyo3.rs/main/class

struct X86FlagsRegHandler {
    pub eflags: pcode::VarNode,
}

impl icicle_cpu::RegHandler for X86FlagsRegHandler {
    fn read(&mut self, cpu: &mut Cpu) {
        let eflags = icicle_vm::x86::eflags(cpu);
        cpu.write_var::<u32>(self.eflags, eflags);
    }

    fn write(&mut self, cpu: &mut Cpu) {
        let eflags = cpu.read_var::<u32>(self.eflags);
        icicle_vm::x86::set_eflags(cpu, eflags);
    }
}

#[pyclass(eq, eq_int, module = "icicle")]
#[derive(Clone, Debug, PartialEq)]
pub enum MemoryProtection {
    NoAccess,
    ReadOnly,
    ReadWrite,
    ExecuteOnly,
    ExecuteRead,
    ExecuteReadWrite,
}

#[pyclass(eq, eq_int, module = "icicle")]
#[derive(Clone, Debug, PartialEq)]
pub enum RunStatus {
    /// The VM is still running.
    Running,

    /// The VM exited because it reached instruction count limit.
    InstructionLimit,

    /// The VM exited because it reached a breakpoint.
    Breakpoint,

    /// The VM exited because the interrupt flag was set.
    Interrupted,

    /// The VM has halted.
    Halt,

    /// Killed by an environment specific mechanism.
    Killed,

    /// A deadlock was detected.
    Deadlock,

    /// MMU was unable to allocate memory for an operation.
    OutOfMemory,

    /// Internal error where the emulator reached unimplemented code.
    Unimplemented,

    /// The VM exited due to a unhandled exception.
    UnhandledException,
}

#[pyclass(eq, eq_int, module = "icicle")]
#[derive(Clone, Debug, PartialEq)]
pub enum MemoryExceptionCode {
    Unallocated,
    Unmapped,
    UnmappedRegister,
    Uninitialized,
    ReadViolation,
    WriteViolation,
    ExecViolation,
    ReadWatch,
    WriteWatch,
    Unaligned,
    OutOfMemory,
    SelfModifyingCode,
    AddressOverflow,
    Unknown,
}

impl From<MemError> for MemoryExceptionCode {
    fn from(value: MemError) -> Self {
        match value {
            MemError::Unallocated => MemoryExceptionCode::Unallocated,
            MemError::Unmapped => MemoryExceptionCode::Unmapped,
            MemError::UnmappedRegister => MemoryExceptionCode::UnmappedRegister,
            MemError::Uninitalized => MemoryExceptionCode::Uninitialized,
            MemError::ReadViolation => MemoryExceptionCode::ReadViolation,
            MemError::WriteViolation => MemoryExceptionCode::WriteViolation,
            MemError::ExecViolation => MemoryExceptionCode::ExecViolation,
            MemError::ReadWatch => MemoryExceptionCode::ReadWatch,
            MemError::WriteWatch => MemoryExceptionCode::WriteWatch,
            MemError::Unaligned => MemoryExceptionCode::Unaligned,
            MemError::OutOfMemory => MemoryExceptionCode::OutOfMemory,
            MemError::SelfModifyingCode => MemoryExceptionCode::SelfModifyingCode,
            MemError::AddressOverflow => MemoryExceptionCode::AddressOverflow,
            MemError::Unknown => MemoryExceptionCode::Unknown,
        }
    }
}

#[pyclass(eq, eq_int, module = "icicle", name = "ExceptionCode")]
#[derive(Clone, Debug, PartialEq)]
pub enum ExceptionCodePy {
    NoException = 0x0000,

    InstructionLimit = 0x0001,
    Halt = 0x0002,
    Sleep = 0x0003,
    SoftwareBreakpoint = 0x0004,

    Syscall = 0x0101,
    CpuStateChanged = 0x0102,
    DivisionException = 0x0103,

    ReadUnmapped = 0x0201,
    ReadPerm = 0x0202,
    ReadUnaligned = 0x0203,
    ReadWatch = 0x0204,
    ReadUninitialized = 0x0205,

    WriteUnmapped = 0x0301,
    WritePerm = 0x0302,
    WriteWatch = 0x0303,
    WriteUnaligned = 0x0304,

    ExecViolation = 0x0401,
    SelfModifyingCode = 0x0402,
    ExecUnaligned = 0x0403,

    OutOfMemory = 0x0501,
    AddressOverflow = 0x0502,

    InvalidInstruction = 0x1001,
    UnknownInterrupt = 0x1002,
    UnknownCpuID = 0x1003,
    InvalidOpSize = 0x1004,
    InvalidFloatSize = 0x1005,
    CodeNotTranslated = 0x1006,
    ShadowStackOverflow = 0x1007,
    ShadowStackInvalid = 0x1008,
    InvalidTarget = 0x1009,
    UnimplementedOp = 0x100a,

    ExternalAddr = 0x2001,
    Environment = 0x2002,

    JitError = 0x3001,
    InternalError = 0x3002,
    UnmappedRegister = 0x3003,

    UnknownError,
}

impl From<ExceptionCode> for ExceptionCodePy {
    fn from(value: ExceptionCode) -> Self {
        match value {
            ExceptionCode::None => ExceptionCodePy::NoException,
            ExceptionCode::InstructionLimit => ExceptionCodePy::InstructionLimit,
            ExceptionCode::Halt => ExceptionCodePy::Halt,
            ExceptionCode::Sleep => ExceptionCodePy::Sleep,
            ExceptionCode::SoftwareBreakpoint => ExceptionCodePy::SoftwareBreakpoint,
            ExceptionCode::Syscall => ExceptionCodePy::Syscall,
            ExceptionCode::CpuStateChanged => ExceptionCodePy::CpuStateChanged,
            ExceptionCode::DivisionException => ExceptionCodePy::DivisionException,
            ExceptionCode::ReadUnmapped => ExceptionCodePy::ReadUnmapped,
            ExceptionCode::ReadPerm => ExceptionCodePy::ReadPerm,
            ExceptionCode::ReadUnaligned => ExceptionCodePy::ReadUnaligned,
            ExceptionCode::ReadWatch => ExceptionCodePy::ReadWatch,
            ExceptionCode::ReadUninitialized => ExceptionCodePy::ReadUninitialized,
            ExceptionCode::WriteUnmapped => ExceptionCodePy::WriteUnmapped,
            ExceptionCode::WritePerm => ExceptionCodePy::WritePerm,
            ExceptionCode::WriteWatch => ExceptionCodePy::WriteWatch,
            ExceptionCode::WriteUnaligned => ExceptionCodePy::WriteUnaligned,
            ExceptionCode::ExecViolation => ExceptionCodePy::ExecViolation,
            ExceptionCode::SelfModifyingCode => ExceptionCodePy::SelfModifyingCode,
            ExceptionCode::ExecUnaligned => ExceptionCodePy::ExecUnaligned,
            ExceptionCode::OutOfMemory => ExceptionCodePy::OutOfMemory,
            ExceptionCode::AddressOverflow => ExceptionCodePy::AddressOverflow,
            ExceptionCode::InvalidInstruction => ExceptionCodePy::InvalidInstruction,
            ExceptionCode::UnknownInterrupt => ExceptionCodePy::UnknownInterrupt,
            ExceptionCode::UnknownCpuID => ExceptionCodePy::UnknownCpuID,
            ExceptionCode::InvalidOpSize => ExceptionCodePy::InvalidOpSize,
            ExceptionCode::InvalidFloatSize => ExceptionCodePy::InvalidFloatSize,
            ExceptionCode::CodeNotTranslated => ExceptionCodePy::CodeNotTranslated,
            ExceptionCode::ShadowStackOverflow => ExceptionCodePy::ShadowStackOverflow,
            ExceptionCode::ShadowStackInvalid => ExceptionCodePy::ShadowStackInvalid,
            ExceptionCode::InvalidTarget => ExceptionCodePy::InvalidTarget,
            ExceptionCode::UnimplementedOp => ExceptionCodePy::UnimplementedOp,
            ExceptionCode::ExternalAddr => ExceptionCodePy::ExternalAddr,
            ExceptionCode::Environment => ExceptionCodePy::Environment,
            ExceptionCode::JitError => ExceptionCodePy::JitError,
            ExceptionCode::InternalError => ExceptionCodePy::InternalError,
            ExceptionCode::UnmappedRegister => ExceptionCodePy::UnmappedRegister,
            ExceptionCode::UnknownError => ExceptionCodePy::UnknownError,
        }
    }
}

#[allow(non_snake_case)]
fn raise_MemoryException(message: String, e: MemError) -> PyErr {
    Python::attach(|py| {
        let icicle = py.import("icicle").unwrap();
        let exception = icicle.getattr("MemoryException").unwrap();
        let args = (message, MemoryExceptionCode::from(e));
        let inst = exception.call1(args).unwrap();
        PyErr::from_value(inst)
    })
}

fn convert_protection(protection: MemoryProtection) -> u8 {
    match protection {
        MemoryProtection::NoAccess => perm::NONE,
        MemoryProtection::ReadOnly => perm::READ,
        MemoryProtection::ReadWrite => perm::READ | perm::WRITE,
        MemoryProtection::ExecuteOnly => perm::EXEC,
        MemoryProtection::ExecuteRead => perm::EXEC | perm::READ,
        MemoryProtection::ExecuteReadWrite => perm::EXEC | perm::READ | perm::WRITE,
    }
}

/// Observe-only guest memory hooks that forward each access to a Python
/// callback. The callback must not re-enter the engine (the VM is borrowed
/// for the duration of the run).
struct PyWriteHook {
    cb: PyObject,
}

impl icicle_cpu::mem::WriteHook for PyWriteHook {
    fn write(&mut self, _mem: &mut icicle_cpu::Mmu, addr: u64, value: &[u8]) {
        Python::attach(|py| {
            let data = pyo3::types::PyBytes::new(py, value);
            let _ = self.cb.bind(py).call1((addr, data));
        });
    }
}

struct PyReadHook {
    cb: PyObject,
}

impl icicle_cpu::mem::ReadHook for PyReadHook {
    fn read(&mut self, _mem: &mut icicle_cpu::Mmu, addr: u64, size: u8) -> Option<u64> {
        Python::attach(|py| {
            let _ = self.cb.bind(py).call1((addr, size));
        });
        None // observe only; do not override the value read
    }
}

/// An MMIO region whose reads and writes are *serviced* by Python callbacks,
/// not backed by RAM. On read, `read_cb(addr, size)` supplies the value (as
/// `bytes` of length `size`, or an int written little-endian); on write,
/// `write_cb(addr, data: bytes)` observes the store. A missing callback means
/// reads return zero / writes are dropped. Callbacks must not re-enter the VM.
struct PyIoHandler {
    read_cb: Option<PyObject>,
    write_cb: Option<PyObject>,
}

impl icicle_cpu::mem::IoMemory for PyIoHandler {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), MemError> {
        for b in buf.iter_mut() {
            *b = 0;
        }
        if let Some(cb) = &self.read_cb {
            Python::attach(|py| {
                if let Ok(ret) = cb.bind(py).call1((addr, buf.len())) {
                    if let Ok(bytes) = ret.extract::<Vec<u8>>() {
                        let n = bytes.len().min(buf.len());
                        buf[..n].copy_from_slice(&bytes[..n]);
                    } else if let Ok(v) = ret.extract::<u64>() {
                        let le = v.to_le_bytes();
                        let n = le.len().min(buf.len());
                        buf[..n].copy_from_slice(&le[..n]);
                    }
                }
            });
        }
        Ok(())
    }

    fn write(&mut self, addr: u64, value: &[u8]) -> Result<(), MemError> {
        if let Some(cb) = &self.write_cb {
            Python::attach(|py| {
                let data = pyo3::types::PyBytes::new(py, value);
                let _ = cb.bind(py).call1((addr, data));
            });
        }
        Ok(())
    }
}

#[pyclass(unsendable, module = "icicle")]
pub struct Icicle {
    architecture: String,
    vm: icicle_vm::Vm,
    regs: HashMap<String, NamedRegister>,
    // Named snapshots kept alive on the Python side (index == handle).
    snapshots: Vec<icicle_vm::Snapshot>,
    // Set of basic-block addresses executed, when coverage is enabled.
    coverage: Option<Rc<RefCell<HashSet<u64>>>>,
    // Compare-logging (RedQueen / input-to-state) instrumentation, when enabled.
    cmplog: Option<icicle_fuzzing::cmplog2::CmpLog2Ref>,
}

/// Map a core VmExit to the Python-facing RunStatus enum.
fn to_run_status(exit: VmExit) -> RunStatus {
    match exit {
        VmExit::Running => RunStatus::Running,
        VmExit::InstructionLimit => RunStatus::InstructionLimit,
        VmExit::Breakpoint => RunStatus::Breakpoint,
        VmExit::Interrupted => RunStatus::Interrupted,
        VmExit::Halt => RunStatus::Halt,
        VmExit::Killed => RunStatus::Killed,
        VmExit::Deadlock => RunStatus::Deadlock,
        VmExit::OutOfMemory => RunStatus::OutOfMemory,
        VmExit::Unimplemented => RunStatus::Unimplemented,
        VmExit::UnhandledException(_) => RunStatus::UnhandledException,
    }
}

fn reg_find<'a>(i: &'a Icicle, name: &str) -> PyResult<&'a NamedRegister> {
    let sleigh = &i.vm.cpu.arch.sleigh;
    match sleigh.get_reg(name) {
        None => {
            i.regs.get(name.to_lowercase().as_str())
                .ok_or(
                    PyKeyError::new_err(format!("Register not found: {name}"))
                )
        }
        Some(r) => Ok(r),
    }
}

fn reg_var<'a>(i: &'a Icicle, name: &str) -> PyResult<pcode::VarNode> {
    let var = reg_find(i, name)?.get_var();
    var.ok_or(PyKeyError::new_err(format!("Register var too large: {name}")))
}

#[pymethods]
impl Icicle {
    #[getter]
    pub fn get_icount_limit(&mut self) -> u64 {
        self.vm.icount_limit
    }

    #[setter]
    pub fn set_icount_limit(&mut self, value: u64) {
        self.vm.icount_limit = value;
    }

    #[getter]
    pub fn get_icount(&mut self) -> u64 {
        self.vm.cpu.icount
    }

    #[setter]
    pub fn set_icount(&mut self, value: u64) {
        self.vm.cpu.icount = value;
    }

    #[getter]
    pub fn get_exception_code(&self) -> ExceptionCodePy {
        ExceptionCode::from_u32(self.vm.cpu.exception.code).into()
    }

    #[getter]
    pub fn get_exception_value(&self) -> u64 {
        self.vm.cpu.exception.value
    }

    #[getter]
    pub fn get_architecture(&self) -> String {
        self.architecture.to_string()
    }

    #[getter]
    pub fn get_pc(&self) -> u64 {
        self.vm.cpu.read_pc()
    }

    #[setter]
    pub fn set_pc(&mut self, address: u64) {
        self.vm.cpu.write_pc(address)
    }

    #[getter]
    pub fn get_sp(&mut self) -> u64 {
        self.vm.cpu.read_reg(self.vm.cpu.arch.reg_sp)
    }

    #[setter]
    pub fn set_sp(&mut self, address: u64) {
        self.vm.cpu.write_reg(self.vm.cpu.arch.reg_sp, address)
    }

    #[getter]
    pub fn get_mem_capacity(&self) -> usize {
        self.vm.cpu.mem.capacity()
    }

    #[setter]
    pub fn set_mem_capacity(&mut self, capacity: usize) -> PyResult<()> {
        if self.vm.cpu.mem.set_capacity(capacity) {
            return Ok(());
        }
        Err(
            raise_MemoryException(
                format!("Reducing memory capacity is not supported"),
                MemError::Unknown,
            )
        )
    }

    #[new]
    #[pyo3(signature = (
        architecture,
        jit = true,
        jit_mem = true,
        shadow_stack = false,
        recompilation = true,
        track_uninitialized = false,
        optimize_instructions = true,
        optimize_block = false,
        tracing = false,
        os = "none".to_string(),
        sysroot = "/".to_string(),
    ))]
    pub fn new(
        architecture: String,
        jit: bool,
        jit_mem: bool,
        shadow_stack: bool,
        recompilation: bool,
        track_uninitialized: bool,
        optimize_instructions: bool,
        optimize_block: bool,
        tracing: bool,
        os: String,
        sysroot: String,
    ) -> PyResult<Self> {
        // Prevent mixing '_' and '-'
        if architecture.split("-").count() != 1 {
            return Err(
                PyException::new_err(format!("Bad architecture format: {architecture}"))
            );
        }

        // TODO: support instantiating this multiple times
        if tracing {
            if tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_target(false)
                .try_init().is_err() {
            }
        }

        // Set up the CPU state for the target triple. os="none" is a bare CPU
        // (shellcode); os="linux" wires up the Linux userspace environment
        // (syscall emulation) so a binary can be loaded with linux_load().
        let mut config = icicle_vm::cpu::Config::from_target_triple(
            format!("{architecture}-{os}").as_str()
        );
        if config.triple.architecture == Architecture::Unknown {
            return Err(
                PyException::new_err(format!("Unknown architecture: {architecture}"))
            );
        }

        // Configuration
        config.enable_jit = jit;
        config.enable_jit_mem = jit_mem;
        config.enable_shadow_stack = shadow_stack;
        config.enable_recompilation = recompilation;
        config.track_uninitialized = track_uninitialized;
        config.optimize_instructions = optimize_instructions;
        config.optimize_block = optimize_block;

        let mut vm = icicle_vm::build(&config)
            .map_err(|e| {
                PyException::new_err(format!("VM build error: {e}"))
            })?;

        // For an OS-backed triple, build and attach the environment (e.g. the
        // Linux kernel with a VFS rooted at `sysroot`).
        if config.triple.operating_system == target_lexicon::OperatingSystem::Linux {
            let kconfig = icicle_vm::linux::KernelConfig::default();
            let kernel = icicle_vm::env::build_linux_env(
                &mut vm, &kconfig, std::path::PathBuf::from(&sysroot), true,
            ).map_err(|e| PyException::new_err(format!("Failed to build linux env: {e:?}")))?;
            vm.env = Box::new(kernel);
        }

        // Populate the lowercase register map
        let mut regs = HashMap::new();
        let sleigh = &vm.cpu.arch.sleigh;
        for reg in &sleigh.named_registers {
            let name = sleigh.get_str(reg.name);
            regs.insert(name.to_lowercase(), reg.clone());
        }

        // Special handling for x86 flags
        match config.triple.architecture {
            Architecture::X86_32(_) | Architecture::X86_64 | Architecture::X86_64h => {
                let eflags = sleigh.get_reg("eflags").unwrap().get_var().unwrap();
                let reg_handler = X86FlagsRegHandler { eflags };
                vm.cpu.add_reg_handler(eflags.id, Box::new(reg_handler));
            }
            _ => {}
        }

        Ok(Icicle {
            architecture,
            vm,
            regs,
            snapshots: Vec::new(),
            coverage: None,
            cmplog: None,
        })
    }

    pub fn __str__(&mut self) -> String {
        let arch = &self.vm.cpu.arch;
        let endianness = if arch.sleigh.big_endian {
            "big endian"
        } else {
            "little endian"
        };
        format!("Icicle VM for {0:?} ({endianness})", self.architecture)
    }

    pub fn mem_map(&mut self, address: u64, size: u64, protection: MemoryProtection) -> PyResult<()> {
        let init_perm = if self.vm.cpu.mem.track_uninitialized { perm::NONE } else { perm::INIT };
        let mapping = Mapping {
            perm: convert_protection(protection) | init_perm,
            value: 0,
        };
        if self.vm.cpu.mem.map_memory_len(address, size, mapping) {
            Ok(())
        } else {
            Err(
                raise_MemoryException(
                    format!("Failed to map memory {address:X}[{size:X}]"),
                    MemError::Unknown,
                )
            )
        }
    }

    pub fn mem_unmap(&mut self, address: u64, size: u64) -> PyResult<()> {
        if self.vm.cpu.mem.unmap_memory_len(address, size) {
            Ok(())
        } else {
            Err(
                raise_MemoryException(
                    format!("Failed to unmap memory {address:X}[{size:X}]"),
                    MemError::Unknown,
                )
            )
        }
    }

    pub fn mem_protect(&mut self, address: u64, size: usize, protection: MemoryProtection) -> PyResult<()> {
        self.vm.cpu.mem.update_perm(address, size as u64, convert_protection(protection))
            .map_err(|e| {
                raise_MemoryException(
                    format!("Failed to protect memory {address:X}[{size:X}]"),
                    e,
                )
            })?;
        Ok(())
    }

    pub fn mem_read(&mut self, address: u64, size: usize) -> PyResult<Cow<'_, [u8]>> {
        // Allocate a buffer
        let mut buffer = Vec::with_capacity(size);
        buffer.resize(size, 0);

        // Read the memory
        self.vm.cpu.mem.read_bytes(address, &mut buffer[..], perm::NONE)
            .map_err(|e| {
                raise_MemoryException(
                    format!("Failed to read memory {address:X}[{size:X}]"),
                    e,
                )
            })?;
        Ok(Cow::Owned(buffer))
    }

    pub fn mem_write(&mut self, address: u64, data: Vec<u8>) -> PyResult<()> {
        let size = data.len();
        self.vm.cpu.mem.write_bytes(address, &data[..], perm::NONE)
            .map_err(|e| {
                raise_MemoryException(
                    format!("Failed to write memory {address:X}[{size:X}]"),
                    e,
                )
            })
    }

    pub fn reg_list(&self) -> PyResult<IndexMap<String, (u32, u8)>> {
        let mut result = IndexMap::new();
        let sleigh = &self.vm.cpu.arch.sleigh;
        for reg in &sleigh.named_registers {
            let name = sleigh.get_str(reg.name);
            let var = reg.get_var();
            if let Some(var) = var {
                result.insert(name.to_string(), (reg.offset, var.size));
            }
        }
        Ok(result)
    }

    pub fn reg_offset(&self, name: &str) -> PyResult<u32> {
        Ok(reg_find(self, name)?.offset)
    }

    pub fn reg_size(&self, name: &str) -> PyResult<u8> {
        Ok(reg_var(self, name)?.size)
    }

    pub fn reg_read(&mut self, name: &str) -> PyResult<u64> {
        Ok(self.vm.cpu.read_reg(reg_var(self, name)?))
    }

    /// Read a register's full backing bytes (little-endian), for registers
    /// wider than 64 bits (e.g. XMM/YMM/ZMM, vector and flag aggregates).
    pub fn reg_read_bytes(&mut self, name: &str) -> PyResult<Cow<'_, [u8]>> {
        let var = reg_var(self, name)?;
        match self.vm.cpu.regs.get(var) {
            Some(bytes) => Ok(Cow::Owned(bytes.to_vec())),
            None => Err(PyKeyError::new_err(format!("Register has no backing bytes: {name}"))),
        }
    }

    /// Write a register's full backing bytes (little-endian). Extra bytes are
    /// ignored; a short buffer leaves the remaining bytes unchanged.
    pub fn reg_write_bytes(&mut self, name: &str, data: Vec<u8>) -> PyResult<()> {
        let var = reg_var(self, name)?;
        match self.vm.cpu.regs.get_mut(var) {
            Some(dst) => {
                let n = dst.len().min(data.len());
                dst[..n].copy_from_slice(&data[..n]);
                Ok(())
            }
            None => Err(PyKeyError::new_err(format!("Register has no backing bytes: {name}"))),
        }
    }

    pub fn reg_write(&mut self, name: &str, value: u64) -> PyResult<()> {
        let var = reg_var(self, name)?;
        if var == self.vm.cpu.arch.reg_pc {
            self.vm.cpu.write_pc(value);
        } else {
            self.vm.cpu.write_reg(var, value);
        }
        Ok(())
    }

    pub fn reset(&mut self) {
        self.vm.reset();
    }

    pub fn run(&mut self) -> RunStatus {
        match self.vm.run() {
            VmExit::Running => RunStatus::Running,
            VmExit::InstructionLimit => RunStatus::InstructionLimit,
            VmExit::Breakpoint => RunStatus::Breakpoint,
            VmExit::Interrupted => RunStatus::Interrupted,
            VmExit::Halt => RunStatus::Halt,
            VmExit::Killed => RunStatus::Killed,
            VmExit::Deadlock => RunStatus::Deadlock,
            VmExit::OutOfMemory => RunStatus::OutOfMemory,
            VmExit::Unimplemented => RunStatus::Unimplemented,
            VmExit::UnhandledException(_) => RunStatus::UnhandledException,
        }
    }

    pub fn run_until(&mut self, address: u64) -> RunStatus {
        let breakpoint_added = self.vm.add_breakpoint(address);
        let status = self.run();
        if breakpoint_added {
            self.vm.remove_breakpoint(address);
        }
        status
    }

    pub fn step(&mut self, count: u64) -> RunStatus {
        let old_limit = self.vm.icount_limit;
        self.vm.icount_limit = self.vm.cpu.icount.saturating_add(count);
        let status = self.run();
        self.vm.icount_limit = old_limit;
        status
    }

    pub fn add_breakpoint(&mut self, address: u64) -> bool {
        self.vm.add_breakpoint(address)
    }

    pub fn remove_breakpoint(&mut self, address: u64) -> bool {
        self.vm.remove_breakpoint(address)
    }

    // ---- Extended surface (icicle-vm features beyond the stock binding) ----

    /// Take a full VM snapshot (registers + memory) and return its integer
    /// handle for use with `restore`.
    pub fn snapshot(&mut self) -> usize {
        let snap = self.vm.snapshot();
        self.snapshots.push(snap);
        self.snapshots.len() - 1
    }

    /// Restore a snapshot previously taken with `snapshot`.
    pub fn restore(&mut self, handle: usize) -> PyResult<()> {
        if handle >= self.snapshots.len() {
            return Err(PyKeyError::new_err(format!("Unknown snapshot handle: {handle}")));
        }
        // Disjoint field borrows: &mut self.vm and &self.snapshots are distinct.
        self.vm.restore(&self.snapshots[handle]);
        Ok(())
    }

    /// Number of snapshots currently held.
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Record an internal snapshot keyed by the current instruction count.
    /// Enables `step_back`/`goto_icount` to rewind to earlier points.
    pub fn save_snapshot(&mut self) {
        self.vm.save_snapshot();
    }

    /// Reverse execution: step back `count` instructions (requires a prior
    /// `save_snapshot`, e.g. taken at icount 0). Returns the run status after
    /// re-stepping forward to the target instruction count.
    pub fn step_back(&mut self, count: u64) -> PyResult<RunStatus> {
        match self.vm.step_back(count) {
            Some(exit) => Ok(to_run_status(exit)),
            None => Err(PyException::new_err(
                "step_back failed: no snapshot before the target icount (call save_snapshot first)",
            )),
        }
    }

    /// Time-travel to an absolute instruction count (forwards or, if a snapshot
    /// exists, backwards).
    pub fn goto_icount(&mut self, target: u64) -> PyResult<RunStatus> {
        match self.vm.goto_icount(target) {
            Some(exit) => Ok(to_run_status(exit)),
            None => Err(PyException::new_err(
                "goto_icount failed: no snapshot before the target icount (call save_snapshot first)",
            )),
        }
    }

    /// Current return-address call stack (innermost last).
    pub fn get_callstack(&mut self) -> Vec<u64> {
        self.vm.get_callstack()
    }

    /// Disassembly text for the instruction at `address` using the SLEIGH
    /// semantics (no external disassembler). Lifts the block if needed.
    pub fn get_disasm(&mut self, address: u64) -> Option<String> {
        let _ = self.vm.lift(address);
        self.vm.get_disasm(address).map(|s| s.to_string())
    }

    /// Lifted P-code (the SLEIGH intermediate language) for the block group that
    /// begins at `address`, rendered as text with the original instructions
    /// interleaved. Returns None if the address cannot be lifted. This is the
    /// semantic IR the emulator actually executes — the basis for taint,
    /// symbolic reasoning, and semantic diffing.
    pub fn get_pcode(&mut self, address: u64) -> Option<String> {
        let group = self.vm.lift(address).ok()?;
        group
            .to_string_with_disasm(
                &self.vm.code.blocks,
                &self.vm.cpu.arch.sleigh,
                false,
                &self.vm.code.disasm,
            )
            .ok()
    }

    /// (start, size) pairs for every currently mapped memory range. Works for
    /// any session (including OS-loaded images), unlike wrapper-side region
    /// tracking which only knows about explicitly mapped regions.
    pub fn mem_map_ranges(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        // RangeMap yields inclusive (start, end); size = end - start + 1.
        for (start, end, _entry) in self.vm.cpu.mem.get_mapping().iter() {
            out.push((start, end - start + 1));
        }
        out
    }

    /// (start, length) pairs for every instruction in the block group that
    /// begins at `address`. Empty if the address cannot be lifted.
    pub fn get_block_info(&mut self, address: u64) -> Vec<(u64, u64)> {
        if self.vm.lift(address).is_err() {
            return Vec::new();
        }
        match self.vm.get_block_info(address) {
            Some(info) => info.instructions().collect(),
            None => Vec::new(),
        }
    }

    /// Load an ELF into a Linux-mode VM (os="linux") with argv/env, mapping
    /// its segments, stack and entry point via the emulated Linux loader.
    /// `path` is resolved through the VFS rooted at the session's sysroot.
    #[pyo3(signature = (path, argv = Vec::new(), env = Vec::new()))]
    pub fn linux_load(
        &mut self,
        path: String,
        argv: Vec<String>,
        env: Vec<(String, String)>,
    ) -> PyResult<()> {
        let kernel = self.vm.env.as_mut_any()
            .downcast_mut::<icicle_vm::linux::Kernel>()
            .ok_or_else(|| PyException::new_err(
                "linux_load requires a session created with os=\"linux\"",
            ))?;
        let argv_b: Vec<Vec<u8>> = argv.iter().map(|a| a.clone().into_bytes()).collect();
        let env_b: Vec<(Vec<u8>, Vec<u8>)> =
            env.iter().map(|(k, v)| (k.clone().into_bytes(), v.clone().into_bytes())).collect();
        kernel.process.args.set(path.as_bytes(), &argv_b, &env_b);
        // Disjoint field borrows: &mut self.vm.env (receiver) and &mut self.vm.cpu (arg).
        self.vm.env.load(&mut self.vm.cpu, path.as_bytes())
            .map_err(|e| PyException::new_err(format!("linux_load failed: {e}")))
    }

    // ---- Coverage (block-level) ----

    /// Start recording the set of basic-block addresses that execute. Must be
    /// called before running (instrumentation is injected as blocks are lifted).
    pub fn enable_coverage(&mut self) {
        if self.coverage.is_some() {
            return;
        }
        let set = Rc::new(RefCell::new(HashSet::new()));
        let sink = set.clone();
        let hook = self.vm.cpu.add_hook(Box::new(move |_cpu: &mut Cpu, addr: u64| {
            sink.borrow_mut().insert(addr);
        }));
        icicle_vm::injector::register_block_hook_injector(&mut self.vm, 0, u64::MAX, hook);
        self.coverage = Some(set);
    }

    /// Whether coverage recording is enabled.
    pub fn coverage_enabled(&self) -> bool {
        self.coverage.is_some()
    }

    /// Sorted list of basic-block addresses executed since coverage was enabled.
    pub fn get_coverage(&self) -> Vec<u64> {
        match &self.coverage {
            Some(set) => {
                let mut v: Vec<u64> = set.borrow().iter().copied().collect();
                v.sort_unstable();
                v
            }
            None => Vec::new(),
        }
    }

    /// Number of distinct basic blocks executed.
    pub fn coverage_count(&self) -> usize {
        self.coverage.as_ref().map_or(0, |s| s.borrow().len())
    }

    /// Clear the recorded coverage set (instrumentation stays installed).
    pub fn clear_coverage(&mut self) {
        if let Some(set) = &self.coverage {
            set.borrow_mut().clear();
        }
    }

    // ---- Compare logging (RedQueen / input-to-state) ----

    /// Instrument comparisons so that, during execution, the concrete operand
    /// pairs seen at each compare are recorded. This is the input-to-state /
    /// RedQueen primitive: it tells a fuzzer exactly which bytes a magic-value
    /// or checksum check wants. `instrument_calls=True` also logs memcmp/strcmp
    /// style call-argument comparisons. Install before running.
    #[pyo3(signature = (instrument_calls = false))]
    pub fn enable_cmplog(&mut self, instrument_calls: bool) {
        let cmplog = icicle_fuzzing::cmplog2::CmpLog2Builder::new()
            .instrument_calls(instrument_calls)
            .finish(&mut self.vm);
        cmplog.set_enabled(&mut self.vm.cpu, true);
        self.cmplog = Some(cmplog);
    }

    /// Whether compare logging is currently installed.
    pub fn cmplog_enabled(&self) -> bool {
        self.cmplog.is_some()
    }

    /// Recorded instruction-compare operands: one `(address, kind, pairs)` entry
    /// per instrumented compare site, where `pairs` is the list of `(lhs, rhs)`
    /// values observed there (sign-extended). Empty unless `enable_cmplog` ran.
    pub fn get_cmplog(&mut self) -> Vec<(u64, String, Vec<(i64, i64)>)> {
        let mut out = Vec::new();
        if let Some(cmplog) = &self.cmplog {
            for entry in cmplog.get_inst_log(&mut self.vm.cpu) {
                if entry.values.is_empty() {
                    continue;
                }
                out.push((entry.addr, format!("{:?}", entry.op.kind), entry.values.clone()));
            }
        }
        out
    }

    /// Recorded call-compare operands (memcmp/strcmp style), one
    /// `(address, is_indirect, pairs)` entry per site; each pair is the two
    /// compared byte buffers as hex. Only populated when `enable_cmplog` was
    /// called with `instrument_calls=True`.
    pub fn get_cmplog_calls(&mut self) -> Vec<(u64, bool, Vec<(String, String)>)> {
        let mut out = Vec::new();
        if let Some(cmplog) = &self.cmplog {
            for entry in cmplog.get_call_log(&mut self.vm.cpu) {
                if entry.values.is_empty() {
                    continue;
                }
                let hex_of = |bytes: &[u8]| -> String {
                    bytes.iter().map(|b| format!("{b:02x}")).collect()
                };
                let pairs = entry.values.iter()
                    .map(|(a, b)| (hex_of(a), hex_of(b)))
                    .collect();
                out.push((entry.addr, entry.is_indirect, pairs));
            }
        }
        out
    }

    /// Clear the recorded compare operands (instrumentation stays installed).
    pub fn clear_cmplog(&mut self) {
        if let Some(cmplog) = &self.cmplog {
            cmplog.clear_data(&mut self.vm.cpu);
        }
    }

    // ---- Python-callback hooks (arbitrary instrumentation from the bottom) ----

    /// Call `callback(address)` from Python whenever `address` is executed.
    /// Install before running (hooks are injected as blocks are lifted). The
    /// callback is observe-only: it must not call back into this engine (the VM
    /// is borrowed for the duration of the run).
    pub fn add_py_hook(&mut self, address: u64, callback: PyObject) {
        let cb = callback;
        self.vm.hook_address(address, move |_cpu: &mut Cpu, addr: u64| {
            Python::attach(|py| {
                let _ = cb.bind(py).call1((addr,));
            });
        });
    }

    /// Call `callback(block_start_address)` from Python on every basic-block
    /// entry. This is the general instrumentation primitive (custom coverage,
    /// tracing, taint, ...). Same observe-only / install-before-running rules.
    pub fn add_py_block_hook(&mut self, callback: PyObject) {
        let cb = callback;
        let hook = self.vm.cpu.add_hook(Box::new(move |_cpu: &mut Cpu, addr: u64| {
            Python::attach(|py| {
                let _ = cb.bind(py).call1((addr,));
            });
        }));
        icicle_vm::injector::register_block_hook_injector(&mut self.vm, 0, u64::MAX, hook);
    }

    // ---- Guest memory-access hooks (data watchpoints / taint / tracing) ----

    /// Call `callback(addr, data: bytes)` from Python on every guest *write*
    /// whose starting address falls in `[start, end)` (end-exclusive). Returns
    /// a hook id usable with `remove_mem_write_hook`. Observe-only: the callback
    /// must not call back into this engine. Requires the interpreter
    /// (jit=False) to fire on every access. Install before running.
    pub fn add_mem_write_hook(&mut self, start: u64, end: u64, callback: PyObject) -> Option<u32> {
        self.vm.cpu.mem.add_write_hook(start, end, Box::new(PyWriteHook { cb: callback }))
    }

    /// Remove a write hook by the id returned from `add_mem_write_hook`.
    pub fn remove_mem_write_hook(&mut self, id: u32) -> bool {
        self.vm.cpu.mem.remove_write_hook(id)
    }

    /// Call `callback(addr, size)` from Python on every guest *read* whose
    /// starting address falls in `[start, end)` (end-exclusive). Returns a hook
    /// id usable with `remove_mem_read_hook`. Observe-only (the value read is
    /// never overridden). Same jit=False / install-before-running rules.
    pub fn add_mem_read_hook(&mut self, start: u64, end: u64, callback: PyObject) -> Option<u32> {
        self.vm.cpu.mem.add_read_hook(start, end, Box::new(PyReadHook { cb: callback }))
    }

    /// Remove a read hook by the id returned from `add_mem_read_hook`.
    pub fn remove_mem_read_hook(&mut self, id: u32) -> bool {
        self.vm.cpu.mem.remove_read_hook(id)
    }

    // ---- MMIO: memory-mapped I/O serviced by Python callbacks ----

    /// Map `[start, start+size)` as an MMIO region whose accesses are serviced
    /// by Python, not backed by RAM. `read_cb(addr, size)` returns the value a
    /// read sees (`bytes` of length `size`, or an int written little-endian);
    /// `write_cb(addr, data: bytes)` is called on each write. Either callback
    /// may be None (reads return zero / writes are dropped). Unlike a memory
    /// watchpoint hook, the region has no storage — this models device
    /// registers / peripherals. Returns True if the region was mapped.
    #[pyo3(signature = (start, size, read_cb=None, write_cb=None))]
    pub fn map_mmio(
        &mut self,
        start: u64,
        size: u64,
        read_cb: Option<PyObject>,
        write_cb: Option<PyObject>,
    ) -> bool {
        let handler = self.vm.cpu.mem.register_io_handler(PyIoHandler { read_cb, write_cb });
        self.vm.cpu.mem.map_memory_len(start, size, handler)
    }

    // ---- GDB remote stub ----

    /// Serve a GDB remote stub on `addr` (e.g. "127.0.0.1:1234"). Waits up to
    /// `timeout_secs` for a single GDB client to connect, then serves that
    /// session (blocking) until the client detaches. Attach from another
    /// terminal with: gdb -ex "target remote <addr>".
    ///
    /// This blocks the calling session for the duration of the debug session;
    /// it is meant to be invoked deliberately for interactive debugging.
    #[pyo3(signature = (addr = "127.0.0.1:1234".to_string(), timeout_secs = 30))]
    pub fn gdb_serve(&mut self, addr: String, timeout_secs: u64) -> PyResult<String> {
        use std::net::TcpListener;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind(&addr)
            .map_err(|e| PyException::new_err(format!("Failed to bind {addr}: {e}")))?;
        listener.set_nonblocking(true)
            .map_err(|e| PyException::new_err(format!("{e}")))?;
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        let stream = loop {
            match listener.accept() {
                Ok((s, _peer)) => {
                    s.set_nonblocking(false).ok();
                    break s;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(PyException::new_err(format!(
                            "No GDB client connected to {addr} within {timeout_secs}s"
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(PyException::new_err(format!("accept error: {e}"))),
            }
        };

        use target_lexicon::Architecture as A;
        let result = match self.vm.cpu.arch.triple.architecture {
            A::X86_64 => icicle_gdb::run(stream, &mut icicle_gdb::X64Stub::new(&mut self.vm)),
            A::Arm(_) => icicle_gdb::run(stream, &mut icicle_gdb::ArmStub::new(&mut self.vm)),
            A::Mips32(_) => icicle_gdb::run(stream, &mut icicle_gdb::Mips32Stub::new(&mut self.vm)),
            A::Msp430 => icicle_gdb::run(stream, &mut icicle_gdb::Msp430Stub::new(&mut self.vm)),
            other => {
                return Err(PyException::new_err(format!(
                    "GDB stub unsupported for architecture: {other}"
                )))
            }
        };
        result
            .map(|_| format!("GDB session on {addr} ended"))
            .map_err(|e| PyException::new_err(format!("GDB session error: {e}")))
    }
}

#[pyfunction]
pub fn architectures() -> PyResult<Vec<&'static str>> {
    Ok(vec![
        "i686",
        "x86_64",
        "aarch64",
    ])
}

/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn icicle(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(architectures, m)?)?;
    m.add_class::<Icicle>()?;
    m.add_class::<MemoryProtection>()?;
    m.add_class::<MemoryExceptionCode>()?;
    m.add_class::<RunStatus>()?;
    m.add_class::<ExceptionCodePy>()?;
    Ok(())
}