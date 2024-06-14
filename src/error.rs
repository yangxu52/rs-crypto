/// format error msg to console
#[macro_export]
#[cfg(target = "wasm32-unknown-unknown")]
macro_rules! console_err {
    ($($arg:tt)*) => {
        format!("[RS-Crypto Error]: {},  \nContent", format!($($arg)*))
    };
}
#[macro_export]
#[cfg(not(target = "wasm32-unknown-unknown"))]
macro_rules! console_err {
    ($($arg:tt)*) => {
        format!("[RS-Crypto Error]: {}  ", format!($($arg)*))
    };
}
