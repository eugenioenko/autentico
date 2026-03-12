import { Typography } from "antd";

const { Text } = Typography;

export function makeTip(descriptions: Record<string, string>, docsBase: string) {
  return function tip(name: string) {
    return (
      <>
        {descriptions[name]}
        <br /><br />
        <Text code style={{ fontSize: 11, color: "rgba(255,255,255,0.85)" }}>{name}</Text>
        {" · "}
        <a href={`${docsBase}/#${name}`} target="_blank" rel="noreferrer" style={{ color: "rgba(255,255,255,0.9)" }}>
          ↗
        </a>
      </>
    );
  };
}
