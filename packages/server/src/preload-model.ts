/**
 * Pre-download the BERT model for the cascade classifier.
 * Used during Docker build or as a startup step to avoid
 * cold-start latency on the first deep scan request.
 *
 * Usage: npx tsx packages/server/src/preload-model.ts [modelId]
 */

const modelId = process.argv[2] ?? "Xenova/bert-base-NER";

async function main(): Promise<void> {
  console.log(`Downloading BERT model: ${modelId}`);
  console.log(`Cache directory: ${process.env.TRANSFORMERS_CACHE ?? "(default)"}`);

  const start = performance.now();

  try {
    const { pipeline } = await import("@huggingface/transformers");
    const pipe = await pipeline("token-classification", modelId, {
      dtype: "q8",
      device: "cpu",
    });

    // Run a warmup inference to ensure model is fully loaded
    await (pipe as any)("test", { aggregation_strategy: "simple" });

    const elapsed = ((performance.now() - start) / 1000).toFixed(1);
    console.log(`Model ready in ${elapsed}s`);
  } catch (err) {
    console.error("Failed to download model:", err);
    process.exit(1);
  }
}

main();
