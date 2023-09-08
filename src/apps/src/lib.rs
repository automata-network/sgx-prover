#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "tstd")]
extern crate sgxlib as std;

use std::ffi::CStr;
use std::ops::Deref;
use std::os::raw::c_char;
use std::prelude::v1::*;
use std::sync::Arc;
use std::sync::Mutex;

pub use getargs;

#[cfg(not(feature = "tstd"))]
pub type ExitStatus = usize;
#[cfg(feature = "tstd")]
pub type ExitStatus = std::sgx_types::sgx_status_t;

pub trait App {
    fn run(&self, env: AppEnv) -> Result<(), String>;
    fn terminate(&self);
}

pub trait Getter<T> {
    fn generate(&self) -> T;
}

pub type VarMutex<T> = Var<Mutex<T>>;

#[macro_export]
macro_rules! var_get {
    ($container:ident . $field:ident) => {
        $container.$field.get($container)
    };
}

#[macro_export]
macro_rules! var_cloned {
    ($container:ident . $field:ident) => {
        $container.$field.cloned($container)
    };
}

#[derive(Default)]
pub struct Const<T: Default> {
    val: Mutex<Arc<T>>,
}

impl<T: Default> Const<T> {
    pub fn set(&self, val: T) {
        let mut guard = self.val.lock().unwrap();
        *guard = Arc::new(val);
    }

    pub fn get(&self) -> Arc<T> {
        let guard = self.val.lock().unwrap();
        guard.clone()
    }
}

pub struct Var<T> {
    val: Mutex<Option<Arc<T>>>,
}

impl<T, C> Getter<Mutex<T>> for C
where
    C: Getter<T>,
{
    fn generate(&self) -> Mutex<T> {
        Mutex::new(self.generate())
    }
}

impl<T> Default for Var<T> {
    fn default() -> Self {
        Self {
            val: Mutex::new(None),
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Var<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let val = self.val.lock().unwrap();
        match val.deref() {
            Some(val) => write!(f, "{:?}", val),
            None => write!(f, "{}(None)", std::any::type_name::<T>()),
        }
    }
}

// impl<T> std::ops::Deref for Var<T> {
//     type Target = T;
//     fn deref(&self) -> &Self::Target {
//         {
//             let val = self.val.lock().unwrap();
//             if let Some(val) = val.deref() {
//                 return val.clone();
//             }
//         }
//         panic!("not initialized");
//     }
// }

impl<T> Var<Mutex<T>> {
    pub fn with<F, C, E>(&self, ctx: &C, f: F) -> E
    where
        F: FnOnce(&T) -> E,
        C: Getter<T>,
    {
        let var = self.get(ctx);
        let guard = var.lock().unwrap();
        f(&guard)
    }
}

impl<T> Var<T> {
    pub fn set(&self, t: T) {
        let mut val = self.val.lock().unwrap();
        *val = Some(Arc::new(t));
    }

    pub fn unwrap(&self) -> Arc<T> {
        {
            let val = self.val.lock().unwrap();
            if let Some(val) = val.deref() {
                return val.clone();
            }
        }
        panic!("not initialized");
    }

    pub fn get<C>(&self, ctx: &C) -> Arc<T>
    where
        C: Getter<T>,
    {
        {
            let val = self.val.lock().unwrap();
            if let Some(val) = val.deref() {
                return val.clone();
            }
        }
        let val = Arc::new(ctx.generate());
        let mut raw = self.val.lock().unwrap();
        *raw = Some(val.clone());
        val
    }
}

impl<T: Clone> Var<T> {
    pub fn cloned<C>(&self, ctx: &C) -> T
    where
        C: Getter<T>,
    {
        Arc::as_ref(&self.get(ctx)).clone()
    }
}

#[cfg(feature = "std")]
pub fn set_ctrlc<F>(f: F)
where
    F: FnMut() -> () + 'static + Send,
{
    ctrlc::set_handler(f).unwrap();
}

pub fn parse_args(args: *const c_char) -> Vec<String> {
    let args = unsafe { CStr::from_ptr(args).to_str().unwrap() };
    glog::info!("args: {:?}", args);
    serde_json::from_str(args).unwrap()
}

pub fn terminate<A: App, T: Deref<Target = A>>(app: &T) {
    app.terminate()
}

#[derive(Clone, Debug)]
pub struct AppEnv {
    pub enclave_id: u64,

    pub args: Vec<String>,
}

#[cfg(feature = "tstd")]
pub fn run_enclave<A: App, T: Deref<Target = A>>(
    app: &T,
    enclave_id: u64,
    args: *const c_char,
) -> Result<(), ExitStatus> {
    app.run(AppEnv {
        enclave_id,
        args: parse_args(args),
    })
    .map_err(|err| {
        glog::error!("app exit by {}", err);
        #[cfg(not(feature = "tstd"))]
        return 1usize.into();
        #[cfg(feature = "tstd")]
        return ExitStatus::SGX_ERROR_UNEXPECTED;
    })
}

#[cfg(feature = "std")]
pub fn run_std<A: App>(app: &A) {
    let args = std::env::args().collect();
    let enclave_id = 0;
    app.run(AppEnv { enclave_id, args }).unwrap();
}

pub struct DumpApp;

impl App for DumpApp {
    fn run(&self, env: AppEnv) -> Result<(), String> {
        glog::info!("dump app: {:?}", env);
        Ok(())
    }

    fn terminate(&self) {}
}

#[derive(Debug)]
pub struct Args<'a> {
    pub executable: &'a str,
    pub opts: Vec<getargs::Opt<&'a str>>,
    pub args: Vec<&'a str>,
}

// pub fn args(args: &Vec<String>) -> Args {
//     let mut iter = args.iter();
//     // skip the first arg
//     let executable = iter.next().unwrap();
//     let mut opts = getargs::Options::new(iter.map(|a| a.as_str()));
//     let mut out_opts = Vec::new();
//     while let Some(opt) = opts.next_opt().expect("argument parsing error") {
//         glog::info!("{}", opts.va)
//         out_opts.push(opt);
//     }

//     let mut out_args = Vec::new();
//     for arg in opts.positionals() {
//         out_args.push(arg);
//     }
//     return Args {
//         executable: executable.as_str(),
//         opts: out_opts,
//         args: out_args,
//     };
// }
