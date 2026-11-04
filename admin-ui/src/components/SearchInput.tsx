import { IconSearch, IconX } from "@tabler/icons-react";
import { IconButton, Input } from "@yarcl/react";
import { useEffect, useRef, useState, type ComponentProps } from "react";
import { useDebouncedState } from "../hooks/useDebouncedState";

type SearchInputProps = Omit<ComponentProps<typeof Input>, "onChange" | "value" | "defaultValue" | "type"> & {
  value?: string;
  onSearch: (value: string) => void;
  onValueChange?: (value: string) => void;
};

export default function SearchInput({ value: valueProp, onSearch, onValueChange, placeholder = "Search", ...props }: SearchInputProps) {
  const [own, setOwn] = useState("");
  const value = valueProp ?? own;
  const [query, setQuery] = useDebouncedState(value.trim());
  const lastSearch = useRef(query);

  useEffect(() => {
    if (lastSearch.current !== query) {
      lastSearch.current = query;
      onSearch(query);
    }
  }, [query, onSearch]);

  const change = (next: string) => {
    if (valueProp === undefined) setOwn(next);
    onValueChange?.(next);
    setQuery(next.trim(), next === "");
  };
  return (
    <Input
      {...props}
      className={["search-input", props.className].filter(Boolean).join(" ")}
      type="search"
      aria-label={props["aria-label"] ?? placeholder}
      placeholder={placeholder}
      value={value}
      onChange={(e) => {
        change(e.target.value);
      }}
      onKeyDown={(e) => {
        if (e.key === "Enter") setQuery(value.trim(), true);
      }}
      startContent={<IconSearch aria-hidden="true" className="search-input-icon" />}
      endContent={
        value ? (
          <IconButton
            variant="ghost"
            color="neutral"
            aria-label="Clear search"
            onClick={() => {
              change("");
            }}
          >
            <IconX />
          </IconButton>
        ) : undefined
      }
    />
  );
}
