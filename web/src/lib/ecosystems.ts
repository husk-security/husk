// Group the scanner's ecosystem ids into human families for display. Husk
// detects ~68 ecosystems; the Scan view shows them grouped so the breadth is
// legible at a glance. Release-qualified ids (`debian:12`, `alpine:v3.19`) are
// matched on their base. Unknown ids fall back to "Other" rather than vanishing.

export type EcosystemFamily =
  | "Languages"
  | "OS & distros"
  | "AI, agents & editors"
  | "CI, IaC & containers"
  | "Web platforms"
  | "Other";

// Display order (most relevant to a developer first).
export const FAMILY_ORDER: EcosystemFamily[] = [
  "Languages",
  "AI, agents & editors",
  "OS & distros",
  "CI, IaC & containers",
  "Web platforms",
  "Other",
];

const FAMILY_OF: Record<string, EcosystemFamily> = {};
const put = (family: EcosystemFamily, ids: string[]) => {
  for (const id of ids) FAMILY_OF[id] = family;
};

put("Languages", [
  "npm",
  "yarn",
  "pnpm",
  "bun",
  "deno",
  "shrinkwrap",
  "bower",
  "pypi",
  "poetry",
  "pipenv",
  "uv",
  "pdm",
  "conda",
  "cargo",
  "go",
  "nuget",
  "paket",
  "maven",
  "gradle",
  "sbt",
  "bazel",
  "rubygems",
  "packagist",
  "composer",
  "hex",
  "rebar",
  "gleam",
  "pub",
  "swift",
  "carthage",
  "conan",
  "cocoapods",
  "cran",
  "julia",
  "hackage",
  "stack",
  "opam",
  "clojure",
  "luarocks",
  "nimble",
  "mint",
  "dub",
  "elm",
  "crystal",
  "shards",
  "zig",
  "vcpkg",
  "purescript",
  "cpan",
  "perl",
  "haxe",
  "haxelib",
  "erlang",
  "lua",
  "nim",
  "dlang",
  "native",
  "meson",
  "meson-wrap",
  "buf",
  "jsr",
  "racket",
]);
put("OS & distros", [
  "debian",
  "ubuntu",
  "alpine",
  "arch",
  "rpm",
  "redhat",
  "fedora",
  "opensuse",
  "suse",
  "freebsd",
  "homebrew",
  "nix",
  "nixflake",
  "snap",
  "flatpak",
  "gentoo",
  "chocolatey",
  "scoop",
  "winget",
  "spack",
  "guix",
  "dpkg",
  "apk",
  "pacman",
]);
put("AI, agents & editors", [
  "mcp",
  "vscode-extension",
  "openvsx",
  "chrome-extension",
  "firefox-addon",
  "claude-plugin",
  "ollama",
  "jetbrains",
  "jetbrains-plugin",
  "huggingface",
  "jupyter",
  "openai-gpt",
  "vim",
  "vim-plugin",
  "neovim",
]);
put("CI, IaC & containers", [
  "github-actions",
  "gitlab-ci",
  "terraform",
  "helm",
  "docker",
  "oci",
  "pre-commit",
  "k8s-operator",
  "cicd",
]);
put("Web platforms", ["wordpress", "shopify"]);

/** Base ecosystem key: strips a release qualifier (`debian:12` → `debian`). */
export const baseEcosystem = (id: string) => id.split(":")[0].toLowerCase();

/** The display family for an ecosystem id. */
export function ecosystemFamily(id: string): EcosystemFamily {
  return FAMILY_OF[baseEcosystem(id)] ?? "Other";
}
