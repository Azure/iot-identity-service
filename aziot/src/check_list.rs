pub fn check_list() -> Result<(), crate::Error> {
    // All our text is ASCII, so we can measure text width in bytes rather than
    // using unicode-segmentation to count graphemes.
    let checks = crate::internal::check::all_checks();
    let widest_section_name_len = checks
        .iter()
        .map(|(section_name, _)| section_name.len())
        .max()
        .expect("Have at least one section");

    let section_name_column_width = widest_section_name_len + 1;
    let widest_check_id_len = checks
        .iter()
        .flat_map(|(_, section_checks)| section_checks)
        .map(|check| check.meta().id.len())
        .max()
        .expect("Have at least one check");
    let check_id_column_width = widest_check_id_len + 1;

    println!(
        "{:section_name_column_width$}{:check_id_column_width$}DESCRIPTION",
        "CATEGORY",
        "ID",
        section_name_column_width = section_name_column_width,
        check_id_column_width = check_id_column_width,
    );
    println!();

    for (section_name, section_checks) in &checks {
        for check in section_checks {
            println!(
                "{:section_name_column_width$}{:check_id_column_width$}{}",
                section_name,
                check.meta().id,
                check.meta().description,
                section_name_column_width = section_name_column_width,
                check_id_column_width = check_id_column_width,
            );
        }

        println!();
    }

    Ok(())
}
