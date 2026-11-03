use agent_receipts::canonicalize_bytes as canonicalize;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi(js_name = "canonicalize_bytes")]
pub fn canonicalize_bytes(input: Buffer) -> std::result::Result<Buffer, napi::Error<&'static str>> {
    let copied = input.as_ref().to_vec();
    match canonicalize(&copied) {
        Ok(output) => Ok(Buffer::from(output)),
        // napi copies status.as_ref() into the thrown error's code.
        Err(err) => Err(napi::Error::new(err.code(), err.code())),
    }
}
