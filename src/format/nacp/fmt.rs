use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[repr(u8)]
pub enum StartupUserAccount {
    None = 0,
    Required = 1,
    RequiredWithNetworkServiceAccountAvailable = 2,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[repr(u32)]
pub enum Attribute {
    None = 0,
    Demo = 1,
    RetailInteractiveDisplay = 2,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[repr(u8)]
pub enum Screenshot {
    Allow = 0,
    Deny = 1,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[repr(u8)]
pub enum VideoCapture {
    Disabled = 0,
    Enabled = 1,
    Automatic = 2,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[repr(u8)]
pub enum LogoType {
    LicensedByNintendo = 0,
    Nintendo = 2,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[repr(u8)]
pub enum LogoHandling {
    Auto = 0,
    Manual = 1,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[repr(u8)]
pub enum CrashReport {
    Deny = 0,
    Allow = 1,
}