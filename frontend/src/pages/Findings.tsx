import FindingsTable from "../components/FindingsTable";
import { Card } from "../components/ui";

export default function Findings() {
  return (
    <div className="space-y-4"><h1 className="text-2xl font-bold">Findings</h1>
      <Card><FindingsTable defaultStatus="open" /></Card></div>
  );
}
