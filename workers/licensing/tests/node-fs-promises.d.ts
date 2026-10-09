declare module "node:fs/promises" {
  interface DirectoryEntryV1 {
    readonly name: string;
    isDirectory(): boolean;
    isFile(): boolean;
  }

  export function readdir(
    directory: URL,
    options: { readonly withFileTypes: true },
  ): Promise<DirectoryEntryV1[]>;

  export function readFile(file: URL, encoding: "utf8"): Promise<string>;
}
