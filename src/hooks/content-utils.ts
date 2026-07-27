// Content utilities — helpers to walk and modify ToolResultEvent.content

export interface TextContent {
  type: "text";
  text: string;
}

export interface ImageContent {
  type: "image";
  // Image-specific fields
  [key: string]: unknown;
}

export type ContentItem = TextContent | ImageContent;

export function isTextItem(item: ContentItem): item is TextContent {
  return item.type === "text";
}

/**
 * Maps over text items in content, replacing each with the result of `transform`.
 * Image items pass through untouched.
 */
export function mapTextItems(
  content: ContentItem[],
  transform: (text: string) => string
): ContentItem[] {
  return content.map((item) => {
    if (isTextItem(item)) {
      return { ...item, text: transform(item.text) };
    }
    return item;
  });
}

/**
 * Extracts all text from content (for stats/debugging).
 */
export function extractText(content: ContentItem[]): string[] {
  return content.filter(isTextItem).map((item) => item.text);
}