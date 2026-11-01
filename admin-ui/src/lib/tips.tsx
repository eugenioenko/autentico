import { Link, Stack, Text } from "@yarcl/react";

export function makeTip(descriptions: Record<string, string>, docsBase: string) {
  return function tip(name: string) {
    return (
      <Stack gap="xs">
        <span>{descriptions[name]}</span>
        <Text as="span" textStyle="caption">
          <Text as="span" textStyle="code" inherit>
            {name}
          </Text>
          {" · "}
          <Link href={`${docsBase}/#${name}`} external>
            Docs
          </Link>
        </Text>
      </Stack>
    );
  };
}
