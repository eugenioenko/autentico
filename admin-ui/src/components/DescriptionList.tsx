import type { ReactNode } from "react";
import "./DescriptionList.css";

function DescriptionListRoot({ children }: { children: ReactNode }) {
  return <dl className="description-list">{children}</dl>;
}

function DescriptionItem({ label, children }: { label: ReactNode; children?: ReactNode }) {
  return (
    <div className="description-list-item">
      <dt>{label}</dt>
      <dd>{children ?? "—"}</dd>
    </div>
  );
}

const DescriptionList = Object.assign(DescriptionListRoot, { Item: DescriptionItem });

export default DescriptionList;
