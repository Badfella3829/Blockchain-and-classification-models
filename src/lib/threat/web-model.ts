/** Scores one traffic record with the Random Forest exported by train_model.py --export-web. */
export type FeatureValue = number | string | null | undefined;
export type FeatureRecord = Record<string, FeatureValue>;

export type WebModelBundle = {
  model_version: string;
  features: string[];
  classes: number[];
  numeric: { columns: string[]; medians: number[]; means: number[]; scales: number[] };
  categorical: { columns: string[]; most_frequent: string[]; categories: string[][] };
  trees: { left: number[]; right: number[]; feature: number[]; threshold: number[]; probability: number[] }[];
  metrics?: Record<string, unknown>;
};

const isMissing = (value: FeatureValue) =>
  value === null || value === undefined || (typeof value === "number" && Number.isNaN(value));

export function vectorize(bundle: WebModelBundle, record: FeatureRecord): Float32Array {
  const { numeric, categorical } = bundle;
  const width = numeric.columns.length + categorical.categories.reduce((n, c) => n + c.length, 0);
  // Float32, like scikit-learn's tree comparisons.
  const vector = new Float32Array(width);
  let offset = 0;
  numeric.columns.forEach((column, i) => {
    const raw = record[column];
    const value = isMissing(raw) ? numeric.medians[i]! : Number(raw);
    if (Number.isNaN(value)) throw new Error(`Feature '${column}' must be a number.`);
    vector[offset++] = (value - numeric.means[i]!) / numeric.scales[i]!;
  });
  categorical.columns.forEach((column, i) => {
    const raw = record[column];
    const value = isMissing(raw) ? categorical.most_frequent[i]! : String(raw);
    for (const category of categorical.categories[i]!) vector[offset++] = value === category ? 1 : 0;
  });
  return vector;
}

/** Probability that the record is an attack (class 1). */
export function predictProbability(bundle: WebModelBundle, record: FeatureRecord): number {
  const x = vectorize(bundle, record);
  let total = 0;
  for (const tree of bundle.trees) {
    let node = 0;
    while (tree.left[node] !== -1) {
      node = x[tree.feature[node]!]! <= tree.threshold[node]! ? tree.left[node]! : tree.right[node]!;
    }
    total += tree.probability[node]!;
  }
  return total / bundle.trees.length;
}
