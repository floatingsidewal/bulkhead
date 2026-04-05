/**
 * Main-thread interface to the BERT worker (Layer 2).
 * Manages the worker lifecycle and maps BERT tokens to Detection objects.
 */

import { Worker } from "node:worker_threads";
import { resolve } from "node:path";
import type { Detection, Confidence } from "../types";
import type { WorkerRequest, WorkerResponse, BertToken } from "./bert-worker";

const DEFAULT_MODEL_ID = "gravitee-io/bert-small-pii-detection";

export interface BertLayerConfig {
  modelId?: string;
  /** Threshold above which detections are confirmed, below which they escalate */
  escalationThreshold: number;
}

export class BertLayer {
  private worker: Worker | null = null;
  private pendingRequests = new Map<
    string,
    { resolve: (tokens: BertToken[]) => void; reject: (err: Error) => void }
  >();
  private requestId = 0;
  private config: BertLayerConfig;

  constructor(config?: Partial<BertLayerConfig>) {
    this.config = {
      escalationThreshold: 0.75,
      ...config,
    };
  }

  /** Ensure the worker thread is running */
  private ensureWorker(): Worker {
    if (!this.worker) {
      const workerPath = resolve(__dirname, "bert-worker.js");
      this.worker = new Worker(workerPath);

      this.worker.on("message", (msg: WorkerResponse) => {
        const pending = this.pendingRequests.get(msg.id);
        if (!pending) return;

        this.pendingRequests.delete(msg.id);
        if (msg.type === "error") {
          pending.reject(new Error(msg.error ?? "Unknown worker error"));
        } else {
          pending.resolve(msg.tokens ?? []);
        }
      });

      this.worker.on("error", (err) => {
        // Reject all pending requests
        for (const [id, pending] of this.pendingRequests) {
          pending.reject(err);
          this.pendingRequests.delete(id);
        }
      });
    }
    return this.worker;
  }

  /** Send text to the BERT worker and get raw token results */
  private async analyzeRaw(text: string): Promise<BertToken[]> {
    const worker = this.ensureWorker();
    const id = String(++this.requestId);

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject });
      worker.postMessage({
        type: "analyze",
        id,
        text,
        modelId: this.config.modelId ?? DEFAULT_MODEL_ID,
      } as WorkerRequest);
    });
  }

  /**
   * Analyze text and return Detection objects with escalation disposition.
   * Tokens above the escalation threshold are "confirmed",
   * tokens below are "escalate" (need LLM review).
   */
  async analyze(text: string): Promise<Detection[]> {
    const tokens = await this.analyzeRaw(text);

    return tokens.map((token) => {
      // Strip B-/I- prefix from entity labels (e.g., "B-PERSON" → "PERSON")
      const entityType = token.entity.replace(/^[BI]-/, "");
      const isConfirmed = token.score >= this.config.escalationThreshold;

      const confidence: Confidence =
        token.score >= 0.9 ? "high" : token.score >= 0.7 ? "medium" : "low";

      return {
        entityType,
        start: token.start,
        end: token.end,
        text: token.word,
        confidence,
        score: token.score,
        guardName: "cascade-bert",
        source: "bert" as const,
        context: text.slice(
          Math.max(0, token.start - 150),
          Math.min(text.length, token.end + 150)
        ),
        disposition: isConfirmed ? ("confirmed" as const) : ("escalate" as const),
      };
    });
  }

  /** Terminate the worker thread */
  async dispose(): Promise<void> {
    if (this.worker) {
      await this.worker.terminate();
      this.worker = null;
      this.pendingRequests.clear();
    }
  }
}
