use crate::format::utils::{Reserved64, SigOrPubKey};
use serde_derive::Serialize;

#[repr(C)]
#[derive(Default, Clone, Copy, Serialize)]
pub struct AciFsAccessControl {
    pub version: u8,
    pub padding: [u8; 3],
    pub fs_access_flags_bitmask: [u8; 8], // Work around broken alignment. It sucks.
    pub content_owner_info_offset: u32, // Always 0x1C
    pub content_owner_info_size: u32,
    pub save_data_owner_info_offset: u32,
    pub save_data_owner_info_size: u32,
    // TODO: more variable stuff afterwards?
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy, Serialize)]
pub struct AcidFsAccessControl {
    pub version: u8,
    pub content_owner_id_count: u8, // 5.0.0+
    pub save_data_owner_id_count: u8, // 5.0.0+
    pub padding: u8,
    pub fs_access_flags_bitmask: [u8; 8], // Work around broken alignment. It sucks.
    pub content_owner_id_min: u64,
    pub content_owner_id_max: u64,
    pub save_data_owner_id_min: u64,
    pub save_data_owner_id_max: u64,
    // TODO: more variable stuff afterwards?
}

#[repr(C)]
#[derive(Default, Clone, Copy, Serialize)]
pub struct Meta {
    pub magic: [u8; 4],
    pub signature_key_generation: u32, // 9.0.0+
    #[doc(hidden)]
    reserved8: u32,
    pub flags: u8,
    #[doc(hidden)]
    reserved13: u8,
    pub main_thread_priority: u8,
    pub main_thread_core_number: u8,
    #[doc(hidden)]
    reserved16: u32,
    pub system_resource_size: u32,
    pub version: u32,
    pub main_thread_stack_size: u32,
    pub name: [u8; 16],
    pub product_code: [u8; 16],
    #[doc(hidden)]
    reserved64: Reserved64,
    pub aci_offset: u32,
    pub aci_size: u32,
    pub acid_offset: u32,
    pub acid_size: u32,
}

/// Restriced Access Controls, signed by Nintendo.
#[repr(C)]
#[derive(Default, Clone, Copy, Serialize)]
pub struct Acid {
    // RSA-2048 Signature starting from `rsa_nca_pubkey` and spanning
    // `signed_size` bytes, using a fixed key owned by Nintendo. The pubkey
    // part can be found in hactool, `acid_fixed_key_modulus`.
    //
    // Written separately.
    // rsa_acid_sig: SigOrPubKey, // [u8; 0x100],
    /// RSA-2048 public key for the second NCA signature
    pub rsa_nca_pubkey: SigOrPubKey, // [u8; 0x100],
    /// Magic identifying a valid ACID. Should be `b"ACID"`.
    pub magic: [u8; 4],
    pub signed_size: u32,
    #[doc(hidden)]
    reserved: u32,
    pub flags: u32,
    pub program_id_range_min: u64,
    pub program_id_range_max: u64,
    pub fs_access_control_offset: u32,
    pub fs_access_control_size: u32,
    pub service_access_control_offset: u32,
    pub service_access_control_size: u32,
    pub kernel_access_control_offset: u32,
    pub kernel_access_control_size: u32,
    #[doc(hidden)]
    reserved38: u64
}

/// Access Control Information.
///
/// Protected by the NCA signature, which devs control via their pubkey.
#[repr(C)]
#[derive(Default, Clone, Copy, Serialize)]
pub struct Aci {
    /// Magic identifying a valid ACI. Should be `ACI0`.
    pub magic: [u8; 4],
    #[doc(hidden)]
    reserved4: [u8; 0xC],
    pub program_id: u64,
    #[doc(hidden)]
    reserved24: u64,
    pub fs_access_control_offset: u32,
    pub fs_access_control_size: u32,
    pub service_access_control_offset: u32,
    pub service_access_control_size: u32,
    pub kernel_access_control_offset: u32,
    pub kernel_access_control_size: u32,
    #[doc(hidden)]
    reserved38: u64
}