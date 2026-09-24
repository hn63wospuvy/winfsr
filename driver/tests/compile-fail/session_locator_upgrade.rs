use fsring_core::session::SessionLocator;

pub fn upgrade(locator: SessionLocator) {
    let _ = locator.acquire();
}
