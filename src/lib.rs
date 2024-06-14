mod error;
mod rsa;
mod sha2;

extern crate console_error_panic_hook;
use wasm_bindgen::prelude::*;

use console_error_panic_hook::set_once as set_panic_hook;

#[wasm_bindgen(start)]
pub fn hook() {
    set_panic_hook();
}
