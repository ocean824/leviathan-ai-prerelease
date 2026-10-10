export default function postgres(_connectionString: string, _options?: unknown): never {
  throw new Error("network adapter must not be used in acceptance tests");
}
