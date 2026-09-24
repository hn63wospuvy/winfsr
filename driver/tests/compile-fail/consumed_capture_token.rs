use fsring_core::{
    reqtab::{
        ApplicationCapture, CapturedApplication, CapturedControl, ControlCapture, RequestTable,
    },
    typestate::CompletionSink,
};

pub fn consumed_application_capture<S: CompletionSink, C>(
    table: &mut RequestTable<'_, S, C>,
    application_token: ApplicationCapture,
) {
    let _first = table.install_application_candidate(application_token);
    let _second = table.install_application_candidate(application_token);
}

pub fn consumed_control_capture<S: CompletionSink, C>(
    table: &mut RequestTable<'_, S, C>,
    control_token: ControlCapture,
) {
    let _first = table.install_control_candidate(control_token);
    let _second = table.install_control_candidate(control_token);
}

pub fn consumed_captured_application<S: CompletionSink, C>(
    table: &mut RequestTable<'_, S, C>,
    captured_application: CapturedApplication,
) {
    let _first = table.retain_application(captured_application);
    let _second = table.quarantine_application(captured_application);
}

pub fn consumed_captured_control<S: CompletionSink, C>(
    table: &mut RequestTable<'_, S, C>,
    captured_control: CapturedControl,
) {
    let _first = table.retain_control(captured_control);
    let _second = table.quarantine_control(captured_control);
}
