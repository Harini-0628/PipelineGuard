import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { DecisionBadge, Empty, ErrorBox, Pager, SeverityBadge } from "../components/ui";
import { ApiError } from "../api/client";

describe("ui components", () => {
  it("renders policy decisions distinctly and never colour-only", () => {
    render(<><DecisionBadge decision="FAIL" /><DecisionBadge decision="PASS" /><DecisionBadge decision={null} /></>);
    expect(screen.getByText("FAIL")).toBeInTheDocument();
    expect(screen.getByText("PASS")).toBeInTheDocument();
    expect(screen.getByText("pending")).toBeInTheDocument();
  });
  it("shows severity text", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
  });
  it("error box is an alert and retry works", () => {
    const retry = vi.fn();
    render(<ErrorBox message="boom" onRetry={retry} />);
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
    screen.getByText("Retry").click();
    expect(retry).toHaveBeenCalled();
  });
  it("pager hides when everything fits and pages otherwise", () => {
    const { container, rerender } = render(<Pager total={5} limit={20} offset={0} onChange={() => {}} />);
    expect(container).toBeEmptyDOMElement();
    const change = vi.fn();
    rerender(<Pager total={45} limit={20} offset={0} onChange={change} />);
    screen.getByText("Next").click();
    expect(change).toHaveBeenCalledWith(20);
  });
  it("empty state renders children", () => {
    render(<Empty>nothing here</Empty>);
    expect(screen.getByText("nothing here")).toBeInTheDocument();
  });
  it("ApiError carries status", () => {
    expect(new ApiError(403, "no").status).toBe(403);
    void MemoryRouter;
  });
});
