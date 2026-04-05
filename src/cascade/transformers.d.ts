/** Type stub for @huggingface/transformers — installed as optional dependency */
declare module "@huggingface/transformers" {
  export function pipeline(
    task: string,
    model: string,
    options?: Record<string, unknown>
  ): Promise<(input: string, options?: Record<string, unknown>) => Promise<any[]>>;
}
