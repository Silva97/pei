function _pei() {
    local cmd cmd_index
    local positional_index=0
    local operations=('diff' 'edit' 'flags' 'get' 'inject' 'patch' 'show' 'zeros')
    local current="${COMP_WORDS[COMP_CWORD]}"
    COMPREPLY=()

    # lookup command
    for ((i=1; i < ${#COMP_WORDS[@]}; i++)); do
        if [ "${COMP_WORDS[i]:0:1}" != "-" ]; then
            if [ -z "$cmd" ]; then
                cmd="${COMP_WORDS[i]}"
                cmd_index="$i"
            fi

            let positional_index++
            if [ "$i" == "$COMP_CWORD" ]; then
                break
            fi
        fi
    done

    if [ "$COMP_CWORD" == "$cmd_index" ]; then
        COMPREPLY=( $(compgen -W "${operations[*]}" -- "$current") )
        return 0
    fi

    if [ "$positional_index" != "3" ] || [[ ! "$cmd" =~ ^(edit|get|[eg])$ ]]; then
        COMPREPLY=( $(compgen -W "$(ls -A)" -- "$current") )
        return 0
    fi

    local fields=(
        'coff.machine'
        'coff.number_of_sections'
        'coff.time_date_stamp'
        'coff.pointer_to_symbol_table'
        'coff.number_of_symbols'
        'coff.size_of_optional_header'
        'coff.characteristics'
        'optional.magic'
        'optional.major_linker_version'
        'optional.minor_linker_version'
        'optional.size_of_code'
        'optional.size_of_initialized_data'
        'optional.size_of_unitialized_data'
        'optional.entry_point'
        'optional.base_of_code'
        'optional.image_base'
        'optional.section_alignment'
        'optional.file_alignment'
        'optional.major_os_version'
        'optional.minor_os_version'
        'optional.major_image_version'
        'optional.minor_image_version'
        'optional.major_subsystem_version'
        'optional.minor_subsystem_version'
        'optional.win32_version_value'
        'optional.size_of_image'
        'optional.size_of_headers'
        'optional.checksum'
        'optional.subsystem'
        'optional.dll_characteristics'
        'optional.size_of_stack_reserve'
        'optional.size_of_stack_commit'
        'optional.size_of_head_reserve'
        'optional.size_of_head_commit'
        'optional.loader_flags'
        'optional.number_of_rva_and_sizes'
        'section.'
        'section.0.name'
    )

    local data_directories=(
        'export_table'
        'import_table'
        'resource_table'
        'exception_table'
        'certificate_table'
        'base_relocation_table'
        'debug'
        'architecture'
        'global_ptr'
        'tls_table'
        'load_config_table'
        'bound_import'
        'iat'
        'delay_import_descriptor'
        'clr_runtime_header'
    )

    local section_fields=(
        'name'
        'virtual_size'
        'virtual_address'
        'size_of_raw_data'
        'pointer_to_raw_data'
        'pointer_to_relocations'
        'pointer_to_line_numbers'
        'number_of_relocations'
        'number_of_line_numbers'
        'characteristics'
    )

    for directory in "${data_directories[@]}"; do
        fields+=("optional.$directory.virtual_address" "optional.$directory.size")
    done

    if [ "${current:0:8}" != "section." ]; then
        COMPREPLY=( $(compgen -W "${fields[*]}" -- "$current") )
        return 0
    fi

    local section_number="$(cut -d'.' -f2 <<< "$current")"
    if [[ ! "$section_number" =~ ^[0-9]+$ ]]; then
        return 0
    fi

    for section_field in "${section_fields[@]}"; do
        fields+=("section.$section_number.$section_field")
    done

    COMPREPLY=( $(compgen -W "${fields[*]}" -- "$current") )
    return 0
}

complete -F _pei pei
