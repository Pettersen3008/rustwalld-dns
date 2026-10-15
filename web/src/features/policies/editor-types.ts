import type { Configuration } from "@/lib/api";

export type EditorProps = {
  draft: Configuration;
  edit: (value: Configuration) => void;
};
