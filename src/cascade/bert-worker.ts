/**
 * BERT model worker thread for Layer 2 of the cascading classifier.
 * Runs in a separate thread to avoid blocking the VS Code extension host.
 *
 * Uses @huggingface/transformers to load and run a token-classification model.
 * The model loads lazily on first request and stays loaded (singleton).
 */

import { parentPort } from "node:worker_threads";

/** Message types between main thread and worker */
export interface WorkerRequest {
  type: "analyze" | "dispose";
  id: string;
  text?: string;
  modelId?: string;
}

export interface BertToken {
  entity: string; // e.g., "B-PERSON", "I-LOCATION"
  score: number;
  word: string;
  start: number;
  end: number;
}

export interface WorkerResponse {
  type: "result" | "error" | "ready";
  id: string;
  tokens?: BertToken[];
  error?: string;
}

let pipeline: any = null;
let currentModelId: string | null = null;

async function loadModel(modelId: string): Promise<void> {
  if (pipeline && currentModelId === modelId) return;

  // Dynamic import to avoid loading transformers.js at module level
  const { pipeline: createPipeline } = await import(
    "@huggingface/transformers"
  );

  pipeline = await createPipeline("token-classification", modelId, {
    dtype: "q8",
    // Use ONNX runtime for Node.js
    device: "cpu",
  });
  currentModelId = modelId;
}

async function analyze(
  text: string,
  modelId: string
): Promise<BertToken[]> {
  await loadModel(modelId);

  const results = await pipeline(text, {
    aggregation_strategy: "simple",
  });

  return (results as any[]).map((r) => ({
    entity: r.entity_group ?? r.entity,
    score: r.score,
    word: r.word,
    start: r.start,
    end: r.end,
  }));
}

// Worker message handler
if (parentPort) {
  parentPort.on("message", async (msg: WorkerRequest) => {
    if (msg.type === "dispose") {
      pipeline = null;
      currentModelId = null;
      parentPort!.postMessage({ type: "ready", id: msg.id } as WorkerResponse);
      return;
    }

    if (msg.type === "analyze" && msg.text) {
      try {
        const tokens = await analyze(
          msg.text,
          msg.modelId ?? "gravitee-io/bert-small-pii-detection"
        );
        parentPort!.postMessage({
          type: "result",
          id: msg.id,
          tokens,
        } as WorkerResponse);
      } catch (err) {
        parentPort!.postMessage({
          type: "error",
          id: msg.id,
          error: err instanceof Error ? err.message : String(err),
        } as WorkerResponse);
      }
    }
  });
}
