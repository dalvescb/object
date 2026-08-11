use object::read;
use std::fs;
use std::path::PathBuf;

#[cfg(feature = "goff")]
#[test]
fn goff_base_symbols() {
    use ebcdic::ebcdic::Ebcdic;
    use object::SymbolIndex;

    // Helper function to convert EBCDIC symbol name to ASCII string
    fn ebcdic_name_to_string(name_bytes: &[u8]) -> String {
        let mut ascii_buf = vec![0u8; name_bytes.len()];
        Ebcdic::ebcdic_to_ascii(name_bytes, &mut ascii_buf, name_bytes.len(), false, true);
        String::from_utf8_lossy(&ascii_buf).trim_end_matches('\0').to_string()
    }

    let path_to_obj: PathBuf = ["testfiles", "goff", "base.o"].iter().collect();
    let contents = fs::read(&path_to_obj).expect("Could not read base.o");
    let file = read::goff::GoffFile::parse(&contents[..]).expect("Could not parse base.o");

    // Expected ESD records from base.goffdump
    // Format: (ESDID, Type, Parent, Offset, Length, Name)
    let expected_symbols = vec![
        (
            0x00000001, 0x00, 0x00000000, 0x00000000, 0x00000000, "base#C",
        ),
        (
            0x00000002, 0x01, 0x00000001, 0x00000000, 0x000000FC, "C_CODE",
        ),
        (
            0x00000003, 0x02, 0x00000002, 0x00000000, 0x00000000, "base#C",
        ),
        (
            0x00000004, 0x01, 0x00000001, 0x00000000, 0x00000000, "C_@@PPA2",
        ),
        (
            0x00000005, 0x03, 0x00000004, 0x00000000, 0x00000008, ".&ppa2",
        ),
        (
            0x00000006, 0x01, 0x00000001, 0x00000000, 0x00000022, "B_IDRL",
        ),
        (
            0x00000007, 0x00, 0x00000000, 0x00000000, 0x00000000, "CEEMAIN",
        ),
        (
            0x00000008, 0x01, 0x00000007, 0x00000000, 0x0000000C, "C_DATA",
        ),
        (
            0x00000009, 0x02, 0x00000008, 0x00000000, 0x00000000, "CEEMAIN",
        ),
        (
            0x0000000A, 0x04, 0x00000001, 0x00000000, 0x00000000, "CEESTART",
        ),
        (0x0000000B, 0x02, 0x00000002, 0x00000000, 0x00000000, "main"),
        (
            0x0000000C, 0x04, 0x00000001, 0x00000000, 0x00000000, "printf",
        ),
        (
            0x0000000D, 0x04, 0x00000001, 0x00000000, 0x00000000, "EDCINPL",
        ),
        (
            0x0000000E, 0x00, 0x00000000, 0x00000000, 0x00000000, "CEESTART",
        ),
        (
            0x0000000F, 0x01, 0x0000000E, 0x00000000, 0x0000007C, "C_CODE",
        ),
        (
            0x00000010, 0x02, 0x0000000F, 0x00000000, 0x00000000, "CEESTART",
        ),
        (
            0x00000011, 0x04, 0x0000000E, 0x00000000, 0x00000000, "CEEMAIN",
        ),
        (
            0x00000012, 0x04, 0x0000000E, 0x00000000, 0x00000000, "CEEFMAIN",
        ),
        (
            0x00000013, 0x04, 0x0000000E, 0x00000000, 0x00000000, "CEEBETBL",
        ),
        (
            0x00000014, 0x04, 0x0000000E, 0x00000000, 0x00000000, "CEEROOTA",
        ),
        (
            0x00000015, 0x04, 0x00000001, 0x00000000, 0x00000000, "CEESG003",
        ),
    ];

    // Use symbol_records() to access ALL symbols including ED/SD (internal API)
    let symbol_records = file.symbol_records();

    assert_eq!(
        symbol_records.len(),
        expected_symbols.len(),
        "Expected {} symbols, found {}",
        expected_symbols.len(),
        symbol_records.len()
    );

    // Verify each symbol's properties using internal symbol_records access
    for (
        expected_esdid,
        expected_type,
        expected_parent,
        expected_offset,
        expected_length,
        expected_name,
    ) in expected_symbols.iter()
    {
        let symbol_index = SymbolIndex(*expected_esdid as usize);
        let symbol = symbol_records.get(&symbol_index).expect(&format!(
            "Failed to find symbol with ESDID 0x{:08X}",
            expected_esdid
        ));

        // Check ESDID using public getter
        assert_eq!(
            symbol.esdid(),
            *expected_esdid,
            "ESDID mismatch for symbol '{}'",
            expected_name
        );

        // Check symbol type using public getter
        assert_eq!(
            symbol.symbol_type(),
            object::goff::SymbolType(*expected_type),
            "Symbol type mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check parent ESDID using public getter
        assert_eq!(
            symbol.parent_esdid().0,
            *expected_parent as usize,
            "Parent ESDID mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check offset using public getter
        assert_eq!(
            symbol.offset(),
            *expected_offset,
            "Offset mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check length using public getter
        assert_eq!(
            symbol.length(),
            *expected_length,
            "Length mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check name by converting EBCDIC to ASCII
        let symbol_name = ebcdic_name_to_string(symbol.name_bytes_owned());
        assert_eq!(
            symbol_name, *expected_name,
            "Name mismatch for ESDID 0x{:08X}",
            expected_esdid
        );
    }
}

#[cfg(feature = "goff")]
#[test]
fn goff_foo_symbols() {
    use ebcdic::ebcdic::Ebcdic;
    use object::SymbolIndex;

    // Helper function to convert EBCDIC symbol name to ASCII string
    fn ebcdic_name_to_string(name_bytes: &[u8]) -> String {
        let mut ascii_buf = vec![0u8; name_bytes.len()];
        Ebcdic::ebcdic_to_ascii(name_bytes, &mut ascii_buf, name_bytes.len(), false, true);
        String::from_utf8_lossy(&ascii_buf).trim_end_matches('\0').to_string()
    }

    let path_to_obj: PathBuf = ["testfiles", "goff", "foo.o"].iter().collect();
    let contents = fs::read(&path_to_obj).expect("Could not read foo.o");
    let file = read::goff::GoffFile::parse(&contents[..]).expect("Could not parse foo.o");

    // Expected ESD records from foo.goffdump
    // Format: (ESDID, Type, Parent, Offset, Length, Name)
    let expected_symbols = vec![
        (
            0x00000001, 0x00, 0x00000000, 0x00000000, 0x00000000, "foo#C",
        ),
        (
            0x00000002, 0x01, 0x00000001, 0x00000000, 0x00000000, "C_WSA64",
        ),
        (
            0x00000003, 0x03, 0x00000002, 0x00000000, 0x00000002, "foo#S",
        ),
        (
            0x00000004, 0x01, 0x00000001, 0x00000000, 0x000000A4, "C_CODE64",
        ),
        (
            0x00000005, 0x02, 0x00000004, 0x00000000, 0x00000000, "foo#C",
        ),
        (
            0x00000006,
            0x01,
            0x00000001,
            0x00000000,
            0x00000000,
            "C_@@QPPA2",
        ),
        (
            0x00000007, 0x03, 0x00000006, 0x00000000, 0x00000008, ".&ppa2",
        ),
        (
            0x00000008, 0x01, 0x00000001, 0x00000000, 0x00000022, "B_IDRL",
        ),
        (
            0x00000009, 0x04, 0x00000001, 0x00000000, 0x00000000, "CELQSTRT",
        ),
        (0x0000000A, 0x02, 0x00000004, 0x00000040, 0x00000000, "c"),
        (0x0000000B, 0x02, 0x00000004, 0x00000060, 0x00000000, "bar"),
    ];

    // Use symbol_records() to access ALL symbols including ED/SD (internal API)
    let symbol_records = file.symbol_records();

    assert_eq!(
        symbol_records.len(),
        expected_symbols.len(),
        "Expected {} symbols, found {}",
        expected_symbols.len(),
        symbol_records.len()
    );

    // Verify each symbol's properties using internal symbol_records access
    for (
        expected_esdid,
        expected_type,
        expected_parent,
        expected_offset,
        expected_length,
        expected_name,
    ) in expected_symbols.iter()
    {
        let symbol_index = SymbolIndex(*expected_esdid as usize);
        let symbol = symbol_records.get(&symbol_index).expect(&format!(
            "Failed to find symbol with ESDID 0x{:08X}",
            expected_esdid
        ));

        // Check ESDID using public getter
        assert_eq!(
            symbol.esdid(),
            *expected_esdid,
            "ESDID mismatch for symbol '{}'",
            expected_name
        );

        // Check symbol type using public getter
        assert_eq!(
            symbol.symbol_type(),
            object::goff::SymbolType(*expected_type),
            "Symbol type mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check parent ESDID using public getter
        assert_eq!(
            symbol.parent_esdid().0,
            *expected_parent as usize,
            "Parent ESDID mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check offset using public getter
        assert_eq!(
            symbol.offset(),
            *expected_offset,
            "Offset mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check length using public getter
        assert_eq!(
            symbol.length(),
            *expected_length,
            "Length mismatch for ESDID 0x{:08X} ({})",
            expected_esdid,
            expected_name
        );

        // Check name by converting EBCDIC to ASCII
        let symbol_name = ebcdic_name_to_string(symbol.name_bytes_owned());
        assert_eq!(
            symbol_name, *expected_name,
            "Name mismatch for ESDID 0x{:08X}",
            expected_esdid
        );
    }
}

#[cfg(feature = "goff")]
#[test]
fn goff_foo_behavioral_attributes() {
    use object::SymbolIndex;
    use object::goff::*;

    let path_to_obj: PathBuf = ["testfiles", "goff", "foo.o"].iter().collect();
    let contents = fs::read(&path_to_obj).expect("Could not read foo.o");
    let file = read::goff::GoffFile::parse(&contents[..]).expect("Could not parse foo.o");

    // Use symbol_records() to access SD/ED symbols (types 0x00 and 0x01)
    let symbol_records = file.symbol_records();

    // Test behavioral attributes for ESDID 00000001 (foo#C, Sd)
    // Expected BA bytes: 00 00 00 60 00 01 00 00 00 00
    // BA30=3 (RENT) is in byte[3]=0x60, bits 5-7 (IBM bit numbering 0-2)
    // BA54=1 (Section) is in byte[5]=0x01, bits 0-3 (IBM bit numbering 4-7)
    let symbol1 = symbol_records
        .get(&SymbolIndex(0x00000001))
        .expect("Failed to find symbol with ESDID 0x00000001");
    let flags1 = symbol1.behavioral_flags();
    assert_eq!(
        flags1.amode(),
        GOFF_AMODE_UNSPEC,
        "ESDID 1: AMODE should be Unspec"
    );
    assert_eq!(
        flags1.rmode(),
        GOFF_RMODE_UNSPEC,
        "ESDID 1: RMODE should be Unspec"
    );
    // BA30: byte[3] bits 5-7 = 3 (RENT)
    assert_eq!(
        (flags1.tasking_and_exec >> 5) & 0x07,
        3,
        "ESDID 1: Tasking bits should be 3 (RENT)"
    );
    // BA54: byte[5] bits 0-3 = 1 (Section scope)
    assert_eq!(
        flags1.loading_and_scope & 0x0F,
        1,
        "ESDID 1: Binding scope bits should be 1 (Section)"
    );

    // Test behavioral attributes for ESDID 00000002 (C_WSA64, Ed)
    // Expected BA bytes: 00 04 01 00 00 40 04 00 00 00
    // BA10=04, BA24=1, BA50=1, BA62=1 (XPLINK), BA63=04
    let symbol2 = symbol_records
        .get(&SymbolIndex(0x00000002))
        .expect("Failed to find symbol with ESDID 0x00000002");
    let flags2 = symbol2.behavioral_flags();
    assert_eq!(
        flags2.amode(),
        GOFF_AMODE_UNSPEC,
        "ESDID 2: AMODE should be Unspec"
    );
    assert_eq!(flags2.rmode(), GOFF_RMODE_64, "ESDID 2: RMODE should be 64");
    assert_eq!(
        flags2.text_and_binding & 0x0F,
        1,
        "ESDID 2: BA24 (Binding) should be 1 (Merge)"
    );
    assert_eq!(
        (flags2.loading_and_scope >> 6) & 0x03,
        1,
        "ESDID 2: BA50 (Loading) should be 1 (Deferred)"
    );
    assert!(
        flags2.is_xplink(),
        "ESDID 2: BA62 should indicate XPLINK linkage"
    );
    assert_eq!(
        flags2.linkage_and_align & 0x1F,
        4,
        "ESDID 2: BA63 (Alignment) should be 4 (Quadword)"
    );

    // Test behavioral attributes for ESDID 00000003 (foo#S, Pr)
    // Expected BA bytes: 00 00 00 00 00 00 24 00 00 00
    // BA62=1 (XPLINK), BA63=04 (Quadword alignment)
    let symbol3 = symbol_records
        .get(&SymbolIndex(0x00000003))
        .expect("Failed to find symbol with ESDID 0x00000003");
    let flags3 = symbol3.behavioral_flags();
    assert!(
        flags3.is_xplink(),
        "ESDID 3: BA62 should indicate XPLINK linkage"
    );
    assert_eq!(
        flags3.linkage_and_align & 0x1F,
        4,
        "ESDID 3: BA63 (Alignment) should be 4 (Quadword)"
    );

    // Test behavioral attributes for ESDID 00000004 (C_CODE64, Ed)
    // Expected BA bytes: 00 04 00 00 00 00 04 00 00 00
    // BA10=04 (RMODE 64), BA62=1 (XPLINK)
    let symbol4 = symbol_records
        .get(&SymbolIndex(0x00000004))
        .expect("Failed to find symbol with ESDID 0x00000004");
    let flags4 = symbol4.behavioral_flags();
    assert_eq!(flags4.rmode(), GOFF_RMODE_64, "ESDID 4: RMODE should be 64");
    assert!(
        flags4.is_xplink(),
        "ESDID 4: BA62 should indicate XPLINK linkage"
    );

    // Test behavioral attributes for ESDID 00000005 (foo#C, Ld)
    // Expected BA bytes: 04 00 00 40 00 01 00 00 00 00
    // BA00=04, BA35=2, BA54=1, BA62=0 (Standard OS linkage)
    let symbol5 = symbol_records
        .get(&SymbolIndex(0x00000005))
        .expect("Failed to find symbol with ESDID 0x00000005");
    let flags5 = symbol5.behavioral_flags();
    assert_eq!(flags5.amode(), GOFF_AMODE_64, "ESDID 5: AMODE should be 64");
    assert_eq!(
        flags5.rmode(),
        GOFF_RMODE_UNSPEC,
        "ESDID 5: RMODE should be Unspec"
    );
    assert_eq!(
        flags5.tasking_and_exec & 0x07,
        2,
        "ESDID 5: BA35 (Executable) should be 2 (Code)"
    );
    assert_eq!(
        flags5.loading_and_scope & 0x0F,
        1,
        "ESDID 5: BA54 (Scope) should be 1 (Section)"
    );
    assert!(
        !flags5.is_xplink(),
        "ESDID 5: BA62 should indicate standard OS linkage"
    );
    assert_eq!(
        flags5.linkage_and_align & 0x1F,
        0,
        "ESDID 5: BA63 (Alignment) should be 0 (Byte)"
    );

    // Test behavioral attributes for ESDID 00000009 (CELQSTRT, ErWx)
    // Expected BA bytes: 04 04 00 40 00 04 00 00 00 00
    // BA00=04, BA10=04, BA35=2, BA54=4
    let symbol9 = symbol_records
        .get(&SymbolIndex(0x00000009))
        .expect("Failed to find symbol with ESDID 0x00000009");
    let flags9 = symbol9.behavioral_flags();
    assert_eq!(flags9.amode(), GOFF_AMODE_64, "ESDID 9: AMODE should be 64");
    assert_eq!(flags9.rmode(), GOFF_RMODE_64, "ESDID 9: RMODE should be 64");
    assert_eq!(
        flags9.tasking_and_exec & 0x07,
        2,
        "ESDID 9: BA35 (Executable) should be 2 (Code)"
    );
    assert_eq!(
        flags9.loading_and_scope & 0x0F,
        4,
        "ESDID 9: BA54 (Scope) should be 4 (Import-Export)"
    );
}
