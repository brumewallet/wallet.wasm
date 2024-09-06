import fs from "fs"

const slashes = "/..".repeat(process.env.npm_package_name.split("/").length)

const original = fs.readFileSync("./dist/wasm/Cargo.toml", "utf8")

const replaced = original.replaceAll("../../node_modules", `../..${slashes}`)

fs.writeFileSync("./dist/wasm/Cargo.toml", replaced)