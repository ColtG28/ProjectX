# ProjectX ↔ EMBER Schema Mapping

- EMBER vectorized feature count: 2381
- ProjectX portable feature count: 386
- ProjectX legacy runtime feature count: 13
- Portable coverage ratio after exact/transformable/partial mapping: 0.9974

## Exact Matches

- `null_byte_ratio`
  EMBER source(s): histogram[0]
  Transform: histogram[0] / sum(histogram)
  Notes: Directly encoded by EMBER byte histogram.
- `avg_string_len`
  EMBER source(s): strings.avlength
  Transform: copy
  Notes: Directly encoded by EMBER string stats.
- `pe_num_sections`
  EMBER source(s): section.sections
  Transform: len(section.sections)
  Notes: Direct section count.
- `pe_executable_sections`
  EMBER source(s): section.sections[].props
  Transform: count sections with MEM_EXECUTE
  Notes: Direct section property count.
- `pe_writable_sections`
  EMBER source(s): section.sections[].props
  Transform: count sections with MEM_WRITE
  Notes: Direct section property count.
- `pe_zero_raw_sections`
  EMBER source(s): section.sections[].size
  Transform: count sections where size == 0
  Notes: EMBER section size corresponds to raw size here.
- `pe_suspicious_section_name_hits`
  EMBER source(s): section.sections[].name
  Transform: count names in ProjectX suspicious section-name set
  Notes: Directly derivable from raw section names.
- `pe_network_import_modules`
  EMBER source(s): imports
  Transform: count unique module keys in ProjectX network-module set
  Notes: Directly derivable from raw import map.
- `pe_process_import_modules`
  EMBER source(s): imports
  Transform: count unique module keys in ProjectX process-module set
  Notes: Directly derivable from raw import map.
- `pe_has_cert`
  EMBER source(s): datadirectories[CERTIFICATE_TABLE]
  Transform: 1 if certificate directory size > 0 else 0
  Notes: Directly derivable from EMBER data directories.
- `pe_has_exports`
  EMBER source(s): general.exports, exports
  Transform: 1 if exports > 0 else 0
  Notes: Directly derivable from EMBER general/export data.
- `pe_has_resources`
  EMBER source(s): general.has_resources
  Transform: copy
  Notes: Direct EMBER general field.
- `pe_has_tls`
  EMBER source(s): general.has_tls
  Transform: copy
  Notes: Direct EMBER general field.
- `pe_has_debug`
  EMBER source(s): general.has_debug
  Transform: copy
  Notes: Direct EMBER general field.
- `pe_section_entropy_mean`
  EMBER source(s): section.sections[].entropy
  Transform: mean(section entropies)
  Notes: Directly derivable from raw section entropy values.
- `pe_section_entropy_max`
  EMBER source(s): section.sections[].entropy
  Transform: max(section entropies)
  Notes: Directly derivable from raw section entropy values.
- `pe_high_entropy_sections`
  EMBER source(s): section.sections[].entropy
  Transform: count sections where entropy > 0.8
  Notes: Matches current ProjectX implementation exactly, including its threshold.
- `byte_entropy_00`
  EMBER source(s): byteentropy[0]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_01`
  EMBER source(s): byteentropy[1]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_02`
  EMBER source(s): byteentropy[2]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_03`
  EMBER source(s): byteentropy[3]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_04`
  EMBER source(s): byteentropy[4]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_05`
  EMBER source(s): byteentropy[5]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_06`
  EMBER source(s): byteentropy[6]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_07`
  EMBER source(s): byteentropy[7]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_08`
  EMBER source(s): byteentropy[8]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_09`
  EMBER source(s): byteentropy[9]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_0a`
  EMBER source(s): byteentropy[10]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_0b`
  EMBER source(s): byteentropy[11]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_0c`
  EMBER source(s): byteentropy[12]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_0d`
  EMBER source(s): byteentropy[13]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_0e`
  EMBER source(s): byteentropy[14]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_0f`
  EMBER source(s): byteentropy[15]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_10`
  EMBER source(s): byteentropy[16]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_11`
  EMBER source(s): byteentropy[17]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_12`
  EMBER source(s): byteentropy[18]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_13`
  EMBER source(s): byteentropy[19]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_14`
  EMBER source(s): byteentropy[20]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_15`
  EMBER source(s): byteentropy[21]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_16`
  EMBER source(s): byteentropy[22]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_17`
  EMBER source(s): byteentropy[23]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_18`
  EMBER source(s): byteentropy[24]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_19`
  EMBER source(s): byteentropy[25]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_1a`
  EMBER source(s): byteentropy[26]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_1b`
  EMBER source(s): byteentropy[27]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_1c`
  EMBER source(s): byteentropy[28]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_1d`
  EMBER source(s): byteentropy[29]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_1e`
  EMBER source(s): byteentropy[30]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_1f`
  EMBER source(s): byteentropy[31]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_20`
  EMBER source(s): byteentropy[32]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_21`
  EMBER source(s): byteentropy[33]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_22`
  EMBER source(s): byteentropy[34]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_23`
  EMBER source(s): byteentropy[35]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_24`
  EMBER source(s): byteentropy[36]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_25`
  EMBER source(s): byteentropy[37]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_26`
  EMBER source(s): byteentropy[38]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_27`
  EMBER source(s): byteentropy[39]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_28`
  EMBER source(s): byteentropy[40]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_29`
  EMBER source(s): byteentropy[41]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_2a`
  EMBER source(s): byteentropy[42]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_2b`
  EMBER source(s): byteentropy[43]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_2c`
  EMBER source(s): byteentropy[44]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_2d`
  EMBER source(s): byteentropy[45]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_2e`
  EMBER source(s): byteentropy[46]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_2f`
  EMBER source(s): byteentropy[47]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_30`
  EMBER source(s): byteentropy[48]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_31`
  EMBER source(s): byteentropy[49]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_32`
  EMBER source(s): byteentropy[50]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_33`
  EMBER source(s): byteentropy[51]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_34`
  EMBER source(s): byteentropy[52]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_35`
  EMBER source(s): byteentropy[53]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_36`
  EMBER source(s): byteentropy[54]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_37`
  EMBER source(s): byteentropy[55]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_38`
  EMBER source(s): byteentropy[56]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_39`
  EMBER source(s): byteentropy[57]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_3a`
  EMBER source(s): byteentropy[58]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_3b`
  EMBER source(s): byteentropy[59]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_3c`
  EMBER source(s): byteentropy[60]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_3d`
  EMBER source(s): byteentropy[61]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_3e`
  EMBER source(s): byteentropy[62]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_3f`
  EMBER source(s): byteentropy[63]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_40`
  EMBER source(s): byteentropy[64]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_41`
  EMBER source(s): byteentropy[65]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_42`
  EMBER source(s): byteentropy[66]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_43`
  EMBER source(s): byteentropy[67]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_44`
  EMBER source(s): byteentropy[68]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_45`
  EMBER source(s): byteentropy[69]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_46`
  EMBER source(s): byteentropy[70]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_47`
  EMBER source(s): byteentropy[71]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_48`
  EMBER source(s): byteentropy[72]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_49`
  EMBER source(s): byteentropy[73]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_4a`
  EMBER source(s): byteentropy[74]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_4b`
  EMBER source(s): byteentropy[75]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_4c`
  EMBER source(s): byteentropy[76]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_4d`
  EMBER source(s): byteentropy[77]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_4e`
  EMBER source(s): byteentropy[78]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_4f`
  EMBER source(s): byteentropy[79]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_50`
  EMBER source(s): byteentropy[80]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_51`
  EMBER source(s): byteentropy[81]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_52`
  EMBER source(s): byteentropy[82]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_53`
  EMBER source(s): byteentropy[83]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_54`
  EMBER source(s): byteentropy[84]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_55`
  EMBER source(s): byteentropy[85]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_56`
  EMBER source(s): byteentropy[86]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_57`
  EMBER source(s): byteentropy[87]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_58`
  EMBER source(s): byteentropy[88]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_59`
  EMBER source(s): byteentropy[89]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_5a`
  EMBER source(s): byteentropy[90]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_5b`
  EMBER source(s): byteentropy[91]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_5c`
  EMBER source(s): byteentropy[92]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_5d`
  EMBER source(s): byteentropy[93]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_5e`
  EMBER source(s): byteentropy[94]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_5f`
  EMBER source(s): byteentropy[95]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_60`
  EMBER source(s): byteentropy[96]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_61`
  EMBER source(s): byteentropy[97]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_62`
  EMBER source(s): byteentropy[98]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_63`
  EMBER source(s): byteentropy[99]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_64`
  EMBER source(s): byteentropy[100]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_65`
  EMBER source(s): byteentropy[101]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_66`
  EMBER source(s): byteentropy[102]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_67`
  EMBER source(s): byteentropy[103]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_68`
  EMBER source(s): byteentropy[104]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_69`
  EMBER source(s): byteentropy[105]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_6a`
  EMBER source(s): byteentropy[106]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_6b`
  EMBER source(s): byteentropy[107]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_6c`
  EMBER source(s): byteentropy[108]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_6d`
  EMBER source(s): byteentropy[109]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_6e`
  EMBER source(s): byteentropy[110]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_6f`
  EMBER source(s): byteentropy[111]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_70`
  EMBER source(s): byteentropy[112]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_71`
  EMBER source(s): byteentropy[113]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_72`
  EMBER source(s): byteentropy[114]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_73`
  EMBER source(s): byteentropy[115]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_74`
  EMBER source(s): byteentropy[116]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_75`
  EMBER source(s): byteentropy[117]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_76`
  EMBER source(s): byteentropy[118]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_77`
  EMBER source(s): byteentropy[119]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_78`
  EMBER source(s): byteentropy[120]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_79`
  EMBER source(s): byteentropy[121]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_7a`
  EMBER source(s): byteentropy[122]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_7b`
  EMBER source(s): byteentropy[123]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_7c`
  EMBER source(s): byteentropy[124]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_7d`
  EMBER source(s): byteentropy[125]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_7e`
  EMBER source(s): byteentropy[126]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_7f`
  EMBER source(s): byteentropy[127]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_80`
  EMBER source(s): byteentropy[128]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_81`
  EMBER source(s): byteentropy[129]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_82`
  EMBER source(s): byteentropy[130]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_83`
  EMBER source(s): byteentropy[131]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_84`
  EMBER source(s): byteentropy[132]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_85`
  EMBER source(s): byteentropy[133]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_86`
  EMBER source(s): byteentropy[134]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_87`
  EMBER source(s): byteentropy[135]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_88`
  EMBER source(s): byteentropy[136]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_89`
  EMBER source(s): byteentropy[137]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_8a`
  EMBER source(s): byteentropy[138]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_8b`
  EMBER source(s): byteentropy[139]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_8c`
  EMBER source(s): byteentropy[140]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_8d`
  EMBER source(s): byteentropy[141]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_8e`
  EMBER source(s): byteentropy[142]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_8f`
  EMBER source(s): byteentropy[143]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_90`
  EMBER source(s): byteentropy[144]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_91`
  EMBER source(s): byteentropy[145]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_92`
  EMBER source(s): byteentropy[146]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_93`
  EMBER source(s): byteentropy[147]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_94`
  EMBER source(s): byteentropy[148]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_95`
  EMBER source(s): byteentropy[149]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_96`
  EMBER source(s): byteentropy[150]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_97`
  EMBER source(s): byteentropy[151]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_98`
  EMBER source(s): byteentropy[152]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_99`
  EMBER source(s): byteentropy[153]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_9a`
  EMBER source(s): byteentropy[154]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_9b`
  EMBER source(s): byteentropy[155]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_9c`
  EMBER source(s): byteentropy[156]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_9d`
  EMBER source(s): byteentropy[157]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_9e`
  EMBER source(s): byteentropy[158]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_9f`
  EMBER source(s): byteentropy[159]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_a0`
  EMBER source(s): byteentropy[160]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_a1`
  EMBER source(s): byteentropy[161]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_a2`
  EMBER source(s): byteentropy[162]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_a3`
  EMBER source(s): byteentropy[163]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_a4`
  EMBER source(s): byteentropy[164]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_a5`
  EMBER source(s): byteentropy[165]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_a6`
  EMBER source(s): byteentropy[166]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_a7`
  EMBER source(s): byteentropy[167]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_a8`
  EMBER source(s): byteentropy[168]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_a9`
  EMBER source(s): byteentropy[169]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_aa`
  EMBER source(s): byteentropy[170]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_ab`
  EMBER source(s): byteentropy[171]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_ac`
  EMBER source(s): byteentropy[172]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_ad`
  EMBER source(s): byteentropy[173]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_ae`
  EMBER source(s): byteentropy[174]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_af`
  EMBER source(s): byteentropy[175]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_b0`
  EMBER source(s): byteentropy[176]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_b1`
  EMBER source(s): byteentropy[177]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_b2`
  EMBER source(s): byteentropy[178]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_b3`
  EMBER source(s): byteentropy[179]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_b4`
  EMBER source(s): byteentropy[180]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_b5`
  EMBER source(s): byteentropy[181]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_b6`
  EMBER source(s): byteentropy[182]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_b7`
  EMBER source(s): byteentropy[183]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_b8`
  EMBER source(s): byteentropy[184]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_b9`
  EMBER source(s): byteentropy[185]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_ba`
  EMBER source(s): byteentropy[186]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_bb`
  EMBER source(s): byteentropy[187]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_bc`
  EMBER source(s): byteentropy[188]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_bd`
  EMBER source(s): byteentropy[189]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_be`
  EMBER source(s): byteentropy[190]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_bf`
  EMBER source(s): byteentropy[191]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_c0`
  EMBER source(s): byteentropy[192]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_c1`
  EMBER source(s): byteentropy[193]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_c2`
  EMBER source(s): byteentropy[194]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_c3`
  EMBER source(s): byteentropy[195]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_c4`
  EMBER source(s): byteentropy[196]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_c5`
  EMBER source(s): byteentropy[197]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_c6`
  EMBER source(s): byteentropy[198]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_c7`
  EMBER source(s): byteentropy[199]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_c8`
  EMBER source(s): byteentropy[200]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_c9`
  EMBER source(s): byteentropy[201]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_ca`
  EMBER source(s): byteentropy[202]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_cb`
  EMBER source(s): byteentropy[203]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_cc`
  EMBER source(s): byteentropy[204]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_cd`
  EMBER source(s): byteentropy[205]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_ce`
  EMBER source(s): byteentropy[206]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_cf`
  EMBER source(s): byteentropy[207]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_d0`
  EMBER source(s): byteentropy[208]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_d1`
  EMBER source(s): byteentropy[209]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_d2`
  EMBER source(s): byteentropy[210]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_d3`
  EMBER source(s): byteentropy[211]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_d4`
  EMBER source(s): byteentropy[212]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_d5`
  EMBER source(s): byteentropy[213]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_d6`
  EMBER source(s): byteentropy[214]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_d7`
  EMBER source(s): byteentropy[215]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_d8`
  EMBER source(s): byteentropy[216]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_d9`
  EMBER source(s): byteentropy[217]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_da`
  EMBER source(s): byteentropy[218]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_db`
  EMBER source(s): byteentropy[219]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_dc`
  EMBER source(s): byteentropy[220]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_dd`
  EMBER source(s): byteentropy[221]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_de`
  EMBER source(s): byteentropy[222]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_df`
  EMBER source(s): byteentropy[223]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_e0`
  EMBER source(s): byteentropy[224]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_e1`
  EMBER source(s): byteentropy[225]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_e2`
  EMBER source(s): byteentropy[226]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_e3`
  EMBER source(s): byteentropy[227]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_e4`
  EMBER source(s): byteentropy[228]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_e5`
  EMBER source(s): byteentropy[229]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_e6`
  EMBER source(s): byteentropy[230]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_e7`
  EMBER source(s): byteentropy[231]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_e8`
  EMBER source(s): byteentropy[232]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_e9`
  EMBER source(s): byteentropy[233]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_ea`
  EMBER source(s): byteentropy[234]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_eb`
  EMBER source(s): byteentropy[235]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_ec`
  EMBER source(s): byteentropy[236]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_ed`
  EMBER source(s): byteentropy[237]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_ee`
  EMBER source(s): byteentropy[238]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_ef`
  EMBER source(s): byteentropy[239]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_f0`
  EMBER source(s): byteentropy[240]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_f1`
  EMBER source(s): byteentropy[241]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_f2`
  EMBER source(s): byteentropy[242]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_f3`
  EMBER source(s): byteentropy[243]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_f4`
  EMBER source(s): byteentropy[244]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_f5`
  EMBER source(s): byteentropy[245]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_f6`
  EMBER source(s): byteentropy[246]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_f7`
  EMBER source(s): byteentropy[247]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_f8`
  EMBER source(s): byteentropy[248]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_f9`
  EMBER source(s): byteentropy[249]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_fa`
  EMBER source(s): byteentropy[250]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_fb`
  EMBER source(s): byteentropy[251]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_fc`
  EMBER source(s): byteentropy[252]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_fd`
  EMBER source(s): byteentropy[253]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_fe`
  EMBER source(s): byteentropy[254]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.
- `byte_entropy_ff`
  EMBER source(s): byteentropy[255]
  Transform: normalize EMBER byteentropy histogram exactly
  Notes: ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.

## Transformable Features

- `size_log2`
  EMBER source(s): general.size
  Transform: log2(general.size + 1)
  Notes: EMBER stores raw size directly.
- `bytes_examined_log2`
  EMBER source(s): general.size
  Transform: log2(general.size + 1)
  Notes: Assumes no ProjectX truncation on adapted EMBER rows.
- `entropy`
  EMBER source(s): histogram
  Transform: compute Shannon entropy from EMBER byte histogram
  Notes: Lossless derivation from byte histogram.
- `unique_byte_ratio`
  EMBER source(s): histogram
  Transform: nonzero_byte_values / 256
  Notes: Lossless derivation from byte histogram.
- `printable_ratio`
  EMBER source(s): histogram
  Transform: sum(printable byte counts) / total
  Notes: Derived from full byte histogram.
- `ascii_ratio`
  EMBER source(s): histogram
  Transform: sum(byte 0x00..0x7f) / total
  Notes: Derived from full byte histogram.
- `high_byte_ratio`
  EMBER source(s): histogram
  Transform: sum(byte 0x80..0xff) / total
  Notes: Derived from full byte histogram.
- `string_count_log2`
  EMBER source(s): strings.numstrings
  Transform: log2(strings.numstrings + 1)
  Notes: Direct count with ProjectX log scaling.
- `url_string_ratio`
  EMBER source(s): strings.urls, strings.numstrings
  Transform: strings.urls / max(strings.numstrings, 1)
  Notes: EMBER stores URL count, ProjectX expects ratio.
- `path_string_ratio`
  EMBER source(s): strings.paths, strings.numstrings
  Transform: strings.paths / max(strings.numstrings, 1)
  Notes: EMBER stores path count, ProjectX expects ratio.
- `mz_header`
  EMBER source(s): dataset PE constraint
  Transform: 1.0
  Notes: EMBER dataset rows are PE samples.
- `pe_valid`
  EMBER source(s): dataset PE constraint
  Transform: 1.0
  Notes: EMBER raw rows are extracted from successfully parsed PE samples.
- `pe_is_64`
  EMBER source(s): header.optional.magic, header.coff.machine
  Transform: 1 if PE32+ or AMD64 else 0
  Notes: Derived from EMBER header fields.
- `pe_is_dll`
  EMBER source(s): header.coff.characteristics
  Transform: 1 if DLL characteristic present else 0
  Notes: Derived from EMBER header fields.
- `pe_import_function_count_log2`
  EMBER source(s): imports
  Transform: log2(total imported function names + 1)
  Notes: Directly derivable from raw import map.
- `pe_image_size_log2`
  EMBER source(s): general.vsize
  Transform: log2(general.vsize + 1)
  Notes: EMBER general.vsize maps to virtual image size.
- `elf_header`
  EMBER source(s): dataset PE constraint
  Transform: 0.0
  Notes: EMBER benchmark rows are PE files, so non-PE header flags are zero.
- `pdf_header`
  EMBER source(s): dataset PE constraint
  Transform: 0.0
  Notes: EMBER benchmark rows are PE files, so non-PE header flags are zero.
- `zip_header`
  EMBER source(s): dataset PE constraint
  Transform: 0.0
  Notes: EMBER benchmark rows are PE files, so non-PE header flags are zero.
- `shebang_header`
  EMBER source(s): dataset PE constraint
  Transform: 0.0
  Notes: EMBER benchmark rows are PE files, so non-PE header flags are zero.
- `byte_hist_00`
  EMBER source(s): histogram
  Transform: sum(histogram[0:8]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_01`
  EMBER source(s): histogram
  Transform: sum(histogram[8:16]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_02`
  EMBER source(s): histogram
  Transform: sum(histogram[16:24]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_03`
  EMBER source(s): histogram
  Transform: sum(histogram[24:32]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_04`
  EMBER source(s): histogram
  Transform: sum(histogram[32:40]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_05`
  EMBER source(s): histogram
  Transform: sum(histogram[40:48]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_06`
  EMBER source(s): histogram
  Transform: sum(histogram[48:56]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_07`
  EMBER source(s): histogram
  Transform: sum(histogram[56:64]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_08`
  EMBER source(s): histogram
  Transform: sum(histogram[64:72]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_09`
  EMBER source(s): histogram
  Transform: sum(histogram[72:80]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_10`
  EMBER source(s): histogram
  Transform: sum(histogram[80:88]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_11`
  EMBER source(s): histogram
  Transform: sum(histogram[88:96]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_12`
  EMBER source(s): histogram
  Transform: sum(histogram[96:104]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_13`
  EMBER source(s): histogram
  Transform: sum(histogram[104:112]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_14`
  EMBER source(s): histogram
  Transform: sum(histogram[112:120]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_15`
  EMBER source(s): histogram
  Transform: sum(histogram[120:128]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_16`
  EMBER source(s): histogram
  Transform: sum(histogram[128:136]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_17`
  EMBER source(s): histogram
  Transform: sum(histogram[136:144]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_18`
  EMBER source(s): histogram
  Transform: sum(histogram[144:152]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_19`
  EMBER source(s): histogram
  Transform: sum(histogram[152:160]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_20`
  EMBER source(s): histogram
  Transform: sum(histogram[160:168]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_21`
  EMBER source(s): histogram
  Transform: sum(histogram[168:176]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_22`
  EMBER source(s): histogram
  Transform: sum(histogram[176:184]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_23`
  EMBER source(s): histogram
  Transform: sum(histogram[184:192]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_24`
  EMBER source(s): histogram
  Transform: sum(histogram[192:200]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_25`
  EMBER source(s): histogram
  Transform: sum(histogram[200:208]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_26`
  EMBER source(s): histogram
  Transform: sum(histogram[208:216]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_27`
  EMBER source(s): histogram
  Transform: sum(histogram[216:224]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_28`
  EMBER source(s): histogram
  Transform: sum(histogram[224:232]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_29`
  EMBER source(s): histogram
  Transform: sum(histogram[232:240]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_30`
  EMBER source(s): histogram
  Transform: sum(histogram[240:248]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.
- `byte_hist_31`
  EMBER source(s): histogram
  Transform: sum(histogram[248:256]) / total
  Notes: ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.

## Partial / Approximate Features

- `truncated_input`
  EMBER source(s): general.size
  Transform: set 0 unless an explicit adapter byte cap is applied
  Notes: EMBER raw features are whole-file; ProjectX truncation semantics are not encoded.
- `longest_printable_run_ratio`
  EMBER source(s): strings.avlength, strings.numstrings, imports, exports, section.entry, section.sections[].name
  Transform: lower-bound estimate from known printable metadata strings and EMBER string statistics
  Notes: EMBER raw rows do not preserve full contiguous printable runs, so this is only a lower-bound estimate.
- `max_string_len_log2`
  EMBER source(s): strings.avlength, imports, exports, section.entry, section.sections[].name
  Transform: log2(lower-bound max printable string length + 1)
  Notes: EMBER raw rows omit true max string length, so this is derived from the longest known metadata string and average string length.
- `suspicious_string_ratio`
  EMBER source(s): strings.urls, strings.paths, strings.registry, strings.MZ, strings.numstrings, imports, exports, section.entry, section.sections[].name
  Transform: (coarse EMBER suspicious counters + suspicious metadata-string hits) / max(numstrings, 1)
  Notes: ProjectX uses raw printable strings; this path uses EMBER counters plus PE metadata strings likely present in bytes.
- `pe_import_descriptor_count`
  EMBER source(s): imports
  Transform: len(unique import-module keys)
  Notes: EMBER raw imports merge duplicate descriptors by module name.
- `pe_suspicious_import_count`
  EMBER source(s): imports
  Transform: count unique module keys matching ProjectX suspicious module set
  Notes: Descriptor-level duplication is not preserved in EMBER raw imports.
- `pe_is_probably_packed`
  EMBER source(s): section.sections[].name, imports
  Transform: 1 if suspicious_section_name_hits > 0 and approximate import_descriptor_count < 3 else 0
  Notes: Depends on an approximate import-descriptor count.
- `pe_entrypoint_ratio`
  EMBER source(s): section.entry, section.sections[].vsize, general.vsize, datadirectories[].virtual_address
  Transform: alignment-aware estimated entrypoint position from inferred PE virtual layout
  Notes: EMBER raw rows expose the entry section name and section sizes, but not raw AddressOfEntryPoint or section virtual addresses.
- `pe_overlay_ratio`
  EMBER source(s): general.size, header.optional.sizeof_headers, section.sections[].size
  Transform: alignment-aware estimated overlay from inferred sequential raw layout
  Notes: EMBER raw rows expose section raw sizes but not raw offsets, so overlay is estimated with inferred file alignment.
- `pe_header_anomaly_score`
  EMBER source(s): header, section.sections
  Transform: approximate anomaly fraction from available header checks
  Notes: ProjectX uses PE offsets and size_of_optional_header checks not present in EMBER raw rows.
- `string_pattern_00`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `http` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_01`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `https` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_02`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `exe` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_03`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `dll` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_04`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `bat` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_05`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `cmd` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_06`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `powershell` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_07`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `net` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_08`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `web` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_09`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `download` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_10`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `upload` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_11`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `connect` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_12`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `server` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_13`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `client` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_14`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `file` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_15`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `path` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_16`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `url` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_17`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `ip` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_18`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `address` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_19`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `port` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_20`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `tcp` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_21`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `udp` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_22`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `socket` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_23`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `bind` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_24`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `listen` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_25`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `accept` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_26`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `send` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_27`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `recv` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_28`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `read` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_29`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `write` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_30`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `open` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_31`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `close` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_32`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `create` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_33`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `delete` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_34`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `copy` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_35`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `move` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_36`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `run` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_37`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `exec` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_38`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `system` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_39`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `shell` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_40`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `bash` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_41`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `sh` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_42`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `python` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_43`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `perl` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_44`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `ruby` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_45`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `java` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_46`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `c#` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_47`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `vb` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_48`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `macro` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.
- `string_pattern_49`
  EMBER source(s): imports, exports, section.entry, section.sections[].name, strings.numstrings, strings.urls, strings.paths, strings.registry, strings.MZ
  Transform: metadata-string hits normalized by EMBER strings.numstrings
  Notes: EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `vba` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.

## Missing in EMBER

- `dos_stub_contains_message`
  EMBER source(s): None
  Transform: set 0.0 sentinel
  Notes: EMBER raw features do not preserve DOS stub bytes or substring presence.

## Missing in ProjectX

- EMBER hashed PE structure features: section_size_hash_*, section_entropy_hash_*, imports_library_hash_*, imports_function_hash_*, exports_hash_*, header_*_hash_*, datadir_*
  Notes: ProjectX portable schema does not currently expose these EMBER-style hashed structural PE feature families.
- EMBER printable character distribution: strings_printabledist_*, strings_entropy, strings_printables
  Notes: ProjectX uses different string-derived features and token ratios instead of EMBER's printable-character histogram.

## Benchmark Integrity Risks

- ProjectX portable schema expects 386 features, while EMBER vectorized schema exposes 2381 dimensions with a different design philosophy.
- ProjectX string-pattern features rely on the raw printable string corpus, but EMBER raw rows only expose aggregate string counts and histograms.
- ProjectX PE overlay and entrypoint-ratio features are not recoverable from EMBER raw rows as currently stored.
- EMBER import data merges duplicate library entries, which weakens descriptor-count parity for some ProjectX PE import heuristics.
- The legacy Rust heuristic FeatureVector in src/ml/features.rs is a separate runtime schema and should not be conflated with portable-model parity.
