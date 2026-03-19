"""
MessageVault Key Registry Smart Contract (PyTeal)

Box storage: each user gets a box keyed by their 32-byte address.
Box value: 32 bytes (encryption public key) + length-prefixed username (up to 32 bytes).

ABI methods:
  - register(byte[32], string) -> void — store/update pk + username, sender pays box MBR
  - get_public_key(address) -> byte[32] — read-only box lookup
  - get_username(address) -> string — read-only
  - is_registered(address) -> bool — read-only
"""

from pyteal import *

# Box key = 32-byte sender address (raw, no prefix)
# Box value layout:
#   bytes 0-31:  encryption public key (32 bytes)
#   bytes 32-33: username length (2 bytes, big-endian)
#   bytes 34+:   username (variable, up to 32 bytes)
# Total max box size: 32 + 2 + 32 = 66 bytes

MAX_USERNAME_LEN = Int(32)
PK_SIZE = Int(32)
LEN_PREFIX_SIZE = Int(2)
MAX_BOX_SIZE = Int(66)  # 32 + 2 + 32

# MBR for a box: 2500 + 400 * (key_size + value_size)
# key_size = 32 bytes, value_size = 66 bytes max
# 2500 + 400 * (32 + 66) = 2500 + 39200 = 41700 microALGO = 0.0417 ALGO
BOX_MBR = Int(41700)


router = Router(
    "MessageVaultRegistry",
    BareCallActions(
        no_op=OnCompleteAction.create_only(Approve()),
        update_application=OnCompleteAction.always(
            Return(Txn.sender() == Global.creator_address())
        ),
        delete_application=OnCompleteAction.always(
            Return(Txn.sender() == Global.creator_address())
        ),
    ),
)


@router.method
def register(pk: abi.StaticBytes[Literal[32]], username: abi.String) -> Expr:
    """Register or update encryption public key and username."""
    sender_key = Txn.sender()
    box_exists = App.box_get(sender_key)
    username_bytes = username.get()
    username_len = Len(username_bytes)

    return Seq(
        box_exists,
        # Validate username length
        Assert(username_len <= MAX_USERNAME_LEN),
        If(
            Not(box_exists.hasValue()),
            # New registration: require MBR payment in preceding txn
            Seq(
                Assert(Global.group_size() >= Int(2)),
                Assert(
                    Gtxn[Txn.group_index() - Int(1)].type_enum()
                    == TxnType.Payment
                ),
                Assert(
                    Gtxn[Txn.group_index() - Int(1)].receiver()
                    == Global.current_application_address()
                ),
                Assert(
                    Gtxn[Txn.group_index() - Int(1)].amount() >= BOX_MBR
                ),
                # Create box with max size
                Pop(App.box_create(sender_key, MAX_BOX_SIZE)),
            ),
        ),
        # Write public key (bytes 0-31)
        App.box_replace(sender_key, Int(0), pk.get()),
        # Write username length (bytes 32-33, big-endian uint16)
        App.box_replace(
            sender_key,
            PK_SIZE,
            Extract(Itob(username_len), Int(6), Int(2)),
        ),
        # Write username (bytes 34+)
        If(
            username_len > Int(0),
            App.box_replace(sender_key, PK_SIZE + LEN_PREFIX_SIZE, username_bytes),
        ),
        Approve(),
    )


@router.method(read_only=True)
def get_public_key(addr: abi.Address) -> Expr:
    """Read the encryption public key for an address."""
    box_value = App.box_get(addr.get())
    return Seq(
        box_value,
        Assert(box_value.hasValue()),
        output := abi.DynamicBytes(),
        output.set(Extract(box_value.value(), Int(0), PK_SIZE)),
        abi.MethodReturn(output),
        Approve(),
    )


@router.method(read_only=True)
def get_username(addr: abi.Address) -> Expr:
    """Read the username for an address."""
    box_value = App.box_get(addr.get())
    return Seq(
        box_value,
        Assert(box_value.hasValue()),
        (name_len := ScratchVar()).store(
            ExtractUint16(box_value.value(), PK_SIZE)
        ),
        output := abi.String(),
        output.set(
            Extract(
                box_value.value(),
                PK_SIZE + LEN_PREFIX_SIZE,
                name_len.load(),
            )
        ),
        abi.MethodReturn(output),
        Approve(),
    )


@router.method(read_only=True)
def is_registered(addr: abi.Address) -> Expr:
    """Check if an address has registered."""
    box_len = App.box_length(addr.get())
    return Seq(
        box_len,
        output := abi.Bool(),
        output.set(box_len.hasValue()),
        abi.MethodReturn(output),
        Approve(),
    )


if __name__ == "__main__":
    import json
    import os

    approval, clear, contract = router.compile_program(
        version=8, optimize=OptimizeOptions(scratch_slots=True)
    )

    out_dir = os.path.dirname(os.path.abspath(__file__))

    with open(os.path.join(out_dir, "approval.teal"), "w") as f:
        f.write(approval)

    with open(os.path.join(out_dir, "clear.teal"), "w") as f:
        f.write(clear)

    with open(os.path.join(out_dir, "abi.json"), "w") as f:
        json.dump(contract.dictify(), f, indent=2)

    print("Contract compiled successfully.")
    print(f"  Approval TEAL: {os.path.join(out_dir, 'approval.teal')}")
    print(f"  Clear TEAL: {os.path.join(out_dir, 'clear.teal')}")
    print(f"  ABI: {os.path.join(out_dir, 'abi.json')}")
