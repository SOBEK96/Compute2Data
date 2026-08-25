import type { Metadata } from "next";

import { ProviderConsole } from "@/components/provider-console";

export const metadata: Metadata = {
  title: "Provider console",
  description: "Manage provider stake, datasets, and execution proofs.",
};

export default function ProviderPage() {
  return <ProviderConsole />;
}
