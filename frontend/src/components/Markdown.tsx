import type { ReactNode } from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

/**
 * Render LLM markdown (headings, bold, lists, tables, code) with dark-theme
 * Tailwind styling — the project has no @tailwindcss/typography plugin, so each
 * element is styled explicitly.
 */
const components: Components = {
  h1: ({ children }) => <h3 className="mb-1 mt-3 text-base font-semibold text-slate-100">{children}</h3>,
  h2: ({ children }) => <h4 className="mb-1 mt-3 text-sm font-semibold text-slate-100">{children}</h4>,
  h3: ({ children }) => <h4 className="mb-1 mt-2 text-sm font-semibold text-slate-200">{children}</h4>,
  h4: ({ children }) => <h5 className="mb-1 mt-2 text-sm font-semibold text-slate-300">{children}</h5>,
  p: ({ children }) => <p className="my-1.5 leading-relaxed">{children}</p>,
  ul: ({ children }) => <ul className="my-1.5 ml-4 list-disc space-y-1">{children}</ul>,
  ol: ({ children }) => <ol className="my-1.5 ml-4 list-decimal space-y-1">{children}</ol>,
  li: ({ children }) => <li className="leading-relaxed">{children}</li>,
  strong: ({ children }) => <strong className="font-semibold text-slate-100">{children}</strong>,
  em: ({ children }) => <em className="italic">{children}</em>,
  a: ({ href, children }) => (
    <a href={href} target="_blank" rel="noreferrer" className="text-emerald-400 underline">
      {children}
    </a>
  ),
  code: ({ children }) => (
    <code className="rounded bg-slate-800 px-1 py-0.5 font-mono text-[0.85em] text-emerald-300">
      {children}
    </code>
  ),
  pre: ({ children }) => (
    <pre className="my-2 overflow-auto rounded bg-slate-950 p-2 font-mono text-xs text-slate-200">
      {children}
    </pre>
  ),
  hr: () => <hr className="my-3 border-slate-800" />,
  table: ({ children }) => (
    <div className="my-2 overflow-auto">
      <table className="w-full border-collapse text-xs">{children}</table>
    </div>
  ),
  th: ({ children }) => (
    <th className="border border-slate-700 bg-slate-800 px-2 py-1 text-left font-semibold">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="border border-slate-800 px-2 py-1 align-top">{children}</td>
  ),
  blockquote: ({ children }) => (
    <blockquote className="my-2 border-l-2 border-slate-700 pl-3 text-slate-400">
      {children}
    </blockquote>
  ),
};

export default function Markdown({ children }: { children: string }): ReactNode {
  return (
    <div className="text-sm text-slate-200">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {children}
      </ReactMarkdown>
    </div>
  );
}
