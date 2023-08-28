pub fn get_wine_env(
    pid: pid_t,
) -> Result<Option<(String, HashMap<String, String>)>, std::io::Error> {
    // On linux:
    // Read target env for WINEPREFIX, exec for WINE
    todo!()
}
