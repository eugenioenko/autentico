import { Heading, Inline, Stack, Text } from "@yarcl/react";
import type { ReactNode } from "react";

interface PageHeaderProps {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}

export default function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <Inline gap="md" justify="between" align="center">
      <Stack gap="xs">
        <Heading level={2} textStyle="heading">
          {title}
        </Heading>
        {description && <Text muted>{description}</Text>}
      </Stack>
      {actions && (
        <Inline gap="sm" align="center">
          {actions}
        </Inline>
      )}
    </Inline>
  );
}
