import toml

print(toml.load("Cargo.toml")["package"]["version"].split("-")[0])
