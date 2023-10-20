import wasm from '../../Cargo.toml'

class WASMManager {
  static gm_wasm

  static async getInstance() {
    if (!WASMManager.gm_wasm) {
      WASMManager.gm_wasm = await wasm()
    }
    return WASMManager.gm_wasm
  }
}

export default WASMManager
