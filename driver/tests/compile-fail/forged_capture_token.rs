#[cfg(not(reqtab_request_table_id_probe))]
use fsring_core::reqtab::{
    ApplicationCapture, CapturedApplication, CapturedControl, ControlCapture,
};

#[cfg(reqtab_request_table_id_probe)]
use fsring_core::reqtab::RequestTableId;

#[cfg(reqtab_request_table_id_probe)]
pub fn name_private_table_id(_: RequestTableId) {}

#[cfg(not(reqtab_request_table_id_probe))]
pub fn forged_application_capture(token: ApplicationCapture) {
    let ApplicationCapture {
        table_id: _,
        slot_index: _,
        birth_session_epoch: _,
        birth_generation: _,
        wire_session_epoch: _,
        req_id: _,
        expected_opcode: _,
    } = token;
}

#[cfg(not(reqtab_request_table_id_probe))]
pub fn forged_control_capture(token: ControlCapture) {
    let ControlCapture {
        table_id: _,
        slot_index: _,
        lane: _,
        birth_session_epoch: _,
        birth_generation: _,
        wire_session_epoch: _,
        req_id: _,
        expected_opcode: _,
    } = token;
}

#[cfg(not(reqtab_request_table_id_probe))]
pub fn forged_captured_application(value: CapturedApplication) {
    let CapturedApplication {
        table_id: _,
        slot_index: _,
        birth_session_epoch: _,
        birth_generation: _,
        wire_session_epoch: _,
        req_id: _,
    } = value;
}

#[cfg(not(reqtab_request_table_id_probe))]
pub fn forged_captured_control(value: CapturedControl) {
    let CapturedControl {
        table_id: _,
        slot_index: _,
        lane: _,
        birth_session_epoch: _,
        birth_generation: _,
        wire_session_epoch: _,
        req_id: _,
    } = value;
}
