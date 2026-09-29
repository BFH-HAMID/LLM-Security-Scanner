import { Suspense } from "react";
import { CompareView } from "@/components/CompareView";
import { Spinner } from "@/components/ui";

export const metadata = { title: "Compare runs" };

export default function ComparePage() {
  return (
    <Suspense fallback={<Spinner />}>
      <CompareView />
    </Suspense>
  );
}
