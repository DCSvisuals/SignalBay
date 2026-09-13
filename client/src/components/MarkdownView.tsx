import Markdown from "react-markdown";

export function MarkdownView({ value }: { value: string }) {
  return (
    <div className="md">
      <Markdown>{value}</Markdown>
    </div>
  );
}
