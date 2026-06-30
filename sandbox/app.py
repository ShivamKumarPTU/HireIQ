import gradio as gr
import json
import csv
import io
import os
import pandas as pd
from datetime import datetime

# Import or copy scoring/ranking logic
try:
    import rank
except ImportError:
    # Fallback to absolute or relative imports if run from inside sandbox directory
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import rank

def process_candidates(file_obj):
    if file_obj is None:
        return "Please upload a candidates JSONL or JSON file.", None, None
    
    try:
        content = file_obj.name
        candidates = []
        with open(content, "r", encoding="utf-8") as f:
            first_char = f.read(1)
            f.seek(0)
            if first_char == '[':
                # JSON array
                candidates = json.load(f)
            else:
                # JSONL
                for line in f:
                    if line.strip():
                        candidates.append(json.loads(line))
        
        if not candidates:
            return "No candidates found in the uploaded file.", None, None
        
        # Limit to 100 candidates to prevent resource abuse
        warning_msg = ""
        if len(candidates) > 100:
            candidates = candidates[:100]
            warning_msg = "⚠️ Upload exceeded 100 candidates. Only the first 100 candidates were processed."
        else:
            warning_msg = f"Processed {len(candidates)} candidates successfully."

        # Rank candidates
        scored = []
        for c in candidates:
            cid = c.get("candidate_id")
            if not cid:
                continue
            score = rank.calculate_score(c)
            if score > 0:
                scored.append((cid, score, c))
        
        # Sort
        scored.sort(key=lambda x: (-x[1], x[0]))
        
        # Normalize
        normalized = []
        if scored:
            max_score = scored[0][1]
            if max_score > 0:
                for cid, score, c in scored:
                    rounded_score = round(score / max_score, 4)
                    normalized.append((cid, rounded_score, c))
            else:
                for cid, score, c in scored:
                    normalized.append((cid, 0.0, c))
        else:
            normalized = scored
            
        normalized.sort(key=lambda x: (-x[1], x[0]))
        
        # Prepare output data
        output_rows = []
        preview_rows = []
        for idx, (cid, score, c) in enumerate(normalized):
            r = idx + 1
            reasoning = rank.generate_reasoning(c, r)
            output_rows.append([cid, r, score, reasoning])
            
            # Preview format
            profile = c.get("profile", {})
            preview_rows.append({
                "Rank": r,
                "Candidate ID": cid,
                "Normalized Score": score,
                "Title": profile.get("current_title", "N/A"),
                "Company": profile.get("current_company", "N/A"),
                "Experience": f"{profile.get('years_of_experience', 0.0)}y",
                "Reasoning": reasoning
            })
            
        # Write to memory CSV
        csv_buffer = io.StringIO()
        writer = csv.writer(csv_buffer)
        writer.writerow(["candidate_id", "rank", "score", "reasoning"])
        writer.writerows(output_rows)
        
        # Save temp file
        out_csv_path = "ranked_candidates.csv"
        with open(out_csv_path, "w", encoding="utf-8", newline="") as f:
            f.write(csv_buffer.getvalue())
            
        preview_df = pd.DataFrame(preview_rows) if preview_rows else pd.DataFrame(columns=["Rank", "Candidate ID", "Normalized Score", "Title", "Reasoning"])
        
        return warning_msg, preview_df, out_csv_path
        
    except Exception as e:
        return f"Error processing file: {str(e)}", None, None

# Gradio Interface
theme = gr.themes.Soft(
    primary_hue="red",
    secondary_hue="gray",
    font=[gr.themes.GoogleFont("Outfit"), "Arial", "sans-serif"]
)

css = """
.container { max-width: 900px; margin: auto; padding-top: 1.5rem; }
.header { text-align: center; margin-bottom: 2rem; }
.title { font-size: 2.2rem; font-weight: 800; color: #d32f2f; margin-bottom: 0.5rem; }
.subtitle { font-size: 1.1rem; color: #555; }
.footer { text-align: center; margin-top: 3rem; font-size: 0.9rem; color: #777; }
"""

with gr.Blocks(theme=theme, css=css) as demo:
    with gr.Column(elem_classes="container"):
        gr.Markdown("# HireIQ × Redrob AI Candidate Ranker Sandbox", elem_id="main-title")
        gr.Markdown("Upload a candidate profile file (.json or .jsonl) to rank them using our high-fidelity, honeypot-filtering retrieval heuristic scoring pipeline.", elem_id="subtitle")
        
        with gr.Row():
            with gr.Column(scale=1):
                file_input = gr.File(label="Upload Candidates (JSON/JSONL)", file_types=[".json", ".jsonl"])
                btn = gr.Button("Rank Candidates 🚀", variant="primary")
                
            with gr.Column(scale=2):
                status_out = gr.Textbox(label="Status / Warnings", interactive=False)
                file_output = gr.File(label="Download Ranked CSV Output")
                
        with gr.Row():
            preview_table = gr.DataFrame(label="Top Ranked Candidates Preview", interactive=False)
            
        gr.Markdown("Developed for the Redrob AI Challenge by Team Dhurandhar.", elem_id="footer")
        
    btn.click(
        fn=process_candidates,
        inputs=[file_input],
        outputs=[status_out, preview_table, file_output]
    )

if __name__ == "__main__":
    demo.launch()
