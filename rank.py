import json
import csv
import re
import argparse
import time
from datetime import datetime



# Startup founding dates for honeypot check
FOUNDING_DATES = {
    "Krutrim": (2023, 12),
    "Sarvam AI": (2023, 7),
    "Glance": (2019, 1),
    "Rephrase.ai": (2019, 1),
    "Saarthi.ai": (2017, 1),
    "Observe.AI": (2017, 1),
    "Yellow.ai": (2016, 1),
    "Yellow Messenger": (2016, 1),
    "Niramai": (2016, 1),
    "Wysa": (2015, 1),
    "Verloop.io": (2015, 1),
    "Haptik": (2013, 1),
    "Mad Street Den": (2013, 1),
    # Additional global AI/search startups and platforms
    "OpenAI": (2015, 12),
    "Anthropic": (2021, 2),
    "Cohere": (2019, 6),
    "Hugging Face": (2016, 1),
    "HuggingFace": (2016, 1),
    "Pinecone": (2019, 1),
    "Weaviate": (2020, 1),
    "Qdrant": (2021, 10),
    "LangChain": (2022, 10),
    "LlamaIndex": (2022, 11),
    "Midjourney": (2021, 7)
}

NLP_KEYWORDS = {
    "nlp", "natural language processing", "text mining", "information extraction", 
    "information retrieval", "search", "ranking", "recommendation", "recommender", 
    "semantic search", "neural search", "embeddings", "rag", "retrieval-augmented generation", 
    "vector search", "llm", "large language model", "fine-tuning", "lora", "qlora", "peft"
}

VEC_KEYWORDS = {
    "pinecone", "weaviate", "qdrant", "milvus", "faiss", "elasticsearch", "opensearch",
    "chroma", "sentence-transformers", "transformers", "bge", "e5"
}

EVAL_KEYWORDS = {
    "ndcg", "mrr", "map", "eval", "evaluation", "a/b test", "ab test", "metrics"
}

CONSULTING_COMPANIES = {
    "tcs", "infosys", "wipro", "accenture", "cognizant", "capgemini", "tech mahindra", 
    "mindtree", "hcl", "lti", "ltimindtree", "tata consultancy services"
}

RESEARCH_KEYWORDS = {"university", "lab", "institute", "college", "school", "academy", "research center"}
RESEARCH_TITLES = {"researcher", "research associate", "ph.d candidate", "phd scholar", "professor", "lecturer", "academic", "postdoc"}

CV_SPEECH_KEYWORDS = {
    "computer vision", "image classification", "cnn", "object detection", "yolo", "opencv",
    "speech recognition", "robotics", "ros", "tts", "text-to-speech", "whisper", "asr"
}

MANAGEMENT_TITLES = {"director", "architect", "engineering manager", "manager", "tech lead"}

SHIPPER_KEYWORDS = {"production", "scale", "latency", "deployed", "ab test", "a/b test", "pipeline", "infrastructure", "optimized", "fast", "user", "customer", "shipped", "deploy"}
RESEARCHER_KEYWORDS_INDIVIDUAL = {"academic", "publication", "paper", "research", "citation", "phd", "ph.d", "thesis", "scholar", "labs"}

def parse_date(date_str):
    if not date_str or len(date_str) != 10:
        return None
    try:
        return datetime(int(date_str[:4]), int(date_str[5:7]), int(date_str[8:]))
    except Exception:
        return None

def detect_honeypot(c):
    profile = c.get("profile", {})
    skills = c.get("skills", [])
    career = c.get("career_history", [])
    education = c.get("education", [])
    
    # Check 1: Too many zero duration skills (>=10)
    zero_duration_skills = sum(1 for s in skills if s.get("duration_months", 0) <= 0)
    if zero_duration_skills >= 10:
        return True
        
    # Check 2: Expert/Advanced zero duration skills (>=5)
    expert_zeros = sum(1 for s in skills if s.get("proficiency") in ("expert", "advanced") and s.get("duration_months", 0) == 0)
    if expert_zeros >= 5:
        return True

    # Check 3: Career dates anomalies and startup anomalies
    earliest_start = None
    for job in career:
        start_s = job.get("start_date")
        end_s = job.get("end_date")
        duration = job.get("duration_months", 0)
        comp = job.get("company", "")
        
        start_d = parse_date(start_s)
        end_d = parse_date(end_s) if end_s else datetime(2026, 7, 2)
        
        if start_d:
            if earliest_start is None or start_d < earliest_start:
                earliest_start = start_d
        
        if start_d and end_d:
            cal_months = (end_d.year - start_d.year) * 12 + (end_d.month - start_d.month)
            # Check 3a: job start after end
            if cal_months < 0:
                return True
            # Check 3b: duration exceeds date range by a wide margin
            if duration > cal_months + 6 and duration > 1.5 * cal_months:
                return True
        
        # Check 3c: Startup founding dates violations
        for startup, (f_yr, f_mo) in FOUNDING_DATES.items():
            if startup.lower() in comp.lower():
                if start_d:
                    if start_d.year < f_yr or (start_d.year == f_yr and start_d.month < f_mo):
                        return True
                    ref_date = datetime(2026, 7, 2)
                    max_months = (ref_date.year - f_yr) * 12 + (ref_date.month - f_mo)
                    if duration > max_months + 3:
                        return True

    # Check 4: Years of experience exceeds career span
    years_exp = profile.get("years_of_experience", 0)
    if earliest_start:
        ref_date = datetime(2026, 7, 2)
        max_possible_years = (ref_date - earliest_start).days / 365.25
        if years_exp > max_possible_years + 1.0:
            return True

    # Check 5: Career starts before education
    earliest_edu_start = None
    for edu in education:
        start_yr = edu.get("start_year")
        if start_yr:
            if earliest_edu_start is None or start_yr < earliest_edu_start:
                earliest_edu_start = start_yr
    
    if earliest_start and earliest_edu_start:
        if earliest_start.year < earliest_edu_start - 3:
            return True

    # Check 6: Total job duration exceeds profile years of experience
    total_job_months = sum(job.get("duration_months", 0) for job in career)
    if total_job_months / 12 > years_exp + 3.0:
        return True

    return False

def calculate_score(c):
    profile = c.get("profile", {})
    skills = c.get("skills", [])
    
    # Fast skill keyword check
    skills_names = [s.get("name", "").lower() for s in skills]
    headline = profile.get("headline", "").lower()
    
    has_nlp_skill = any(k in s for s in skills_names for k in NLP_KEYWORDS) or any(k in headline for k in NLP_KEYWORDS)
    has_vec_skill = any(k in s for s in skills_names for k in VEC_KEYWORDS) or any(k in headline for k in VEC_KEYWORDS)
    has_eval_skill = any(k in s for s in skills_names for k in EVAL_KEYWORDS) or any(k in headline for k in EVAL_KEYWORDS)
    
    if not (has_nlp_skill or has_vec_skill or has_eval_skill):
        return 0.0
        
    if detect_honeypot(c):
        return 0.0
        
    career = c.get("career_history", [])
    signals = c.get("redrob_signals", {})
    
    # 1. Experience Score (Ideal 5-9 years)
    years_exp = profile.get("years_of_experience", 0)
    if 5.0 <= years_exp <= 9.0:
        exp_score = 100.0
    elif 4.0 <= years_exp < 5.0:
        exp_score = 80.0
    elif 9.0 < years_exp <= 11.0:
        exp_score = 80.0
    elif 3.0 <= years_exp < 4.0:
        exp_score = 50.0
    elif 11.0 < years_exp <= 13.0:
        exp_score = 40.0
    else:
        exp_score = 10.0
        
    # 2. Skills Matching
    skills_found = {}
    for s in skills:
        name_lower = s.get("name", "").lower()
        prof = s.get("proficiency", "beginner")
        dur = s.get("duration_months", 0)
        ends = s.get("endorsements", 0)
        
        prof_mult = 1.5 if prof == "expert" else (1.2 if prof == "advanced" else (1.0 if prof == "intermediate" else 0.5))
        trust = 1.0 + (ends / 20.0)
        weight = dur * prof_mult * trust
        skills_found[name_lower] = weight
        
    nlp_score = sum(skills_found.get(k, 0) for k in NLP_KEYWORDS if k in skills_found)
    vec_score = sum(skills_found.get(k, 0) for k in VEC_KEYWORDS if k in skills_found)
    eval_score = sum(skills_found.get(k, 0) for k in EVAL_KEYWORDS if k in skills_found)
    
    # Check career history for description keyword hits
    career_nlp_hits = 0
    career_vec_hits = 0
    career_eval_hits = 0
    
    shipper_hits = 0
    researcher_hits = 0
    
    for job in career:
        desc = job.get("description", "").lower()
        title = job.get("title", "").lower()
        
        # NLP hits
        for kw in NLP_KEYWORDS:
            if kw in desc:
                career_nlp_hits += 1.5
        # Vector search hits
        for kw in VEC_KEYWORDS:
            if kw in desc:
                career_vec_hits += 2.0
        # Evaluation metric hits
        for kw in EVAL_KEYWORDS:
            if kw in desc:
                career_eval_hits += 2.5
                
        # Shipper vs Researcher hits
        for kw in SHIPPER_KEYWORDS:
            if kw in desc or kw in title:
                shipper_hits += 1
        for kw in RESEARCHER_KEYWORDS_INDIVIDUAL:
            if kw in desc or kw in title:
                researcher_hits += 1
                
    skills_match_score = (nlp_score * 1.5 + vec_score * 2.0 + eval_score * 2.5 + 
                          career_nlp_hits * 10.0 + career_vec_hits * 15.0 + career_eval_hits * 20.0)
                          
    # 3. Disqualifiers and Penalties
    disqualify_multiplier = 1.0
    
    # Consulting check
    companies = [job.get("company", "").lower() for job in career if job.get("company")]
    if companies:
        all_consulting = all(any(c_firm in comp for c_firm in CONSULTING_COMPANIES) for comp in companies)
        if all_consulting:
            disqualify_multiplier *= 0.05
        elif any(c_firm in companies[0] for c_firm in CONSULTING_COMPANIES):
            # Current job is consulting but has prior product company experience
            disqualify_multiplier *= 0.7
            
    # Academic/Research only check
    has_industry = False
    for job in career:
        comp = job.get("company", "").lower()
        title = job.get("title", "").lower()
        is_acad = any(rk in comp for rk in RESEARCH_KEYWORDS) or any(rt in title for rt in RESEARCH_TITLES)
        if not is_acad:
            has_industry = True
            break
    if not has_industry and len(career) > 0:
        disqualify_multiplier *= 0.05
        
    # Management-only check
    if career:
        recent_job = career[0]
        recent_title = recent_job.get("title", "").lower()
        recent_desc = recent_job.get("description", "").lower()
        if any(mt in recent_title for mt in MANAGEMENT_TITLES):
            coding_words = {"code", "implement", "build", "develop", "train", "model", "pipeline", "deploy", "write", "refactor", "programming", "shipped"}
            if not any(cw in recent_desc for cw in coding_words):
                disqualify_multiplier *= 0.3
                
    # Title chaser / job hopping
    if len(career) > 1:
        total_duration = sum(job.get("duration_months", 0) for job in career)
        avg_tenure = total_duration / len(career)
        if avg_tenure <= 18:
            disqualify_multiplier *= 0.6
            if len(career) >= 3 and avg_tenure <= 15:
                disqualify_multiplier *= 0.4
                
    # Focus mismatch (CV/Speech/Robotics only without NLP)
    has_cv_speech = False
    for s in skills_found:
        if any(k in s for k in CV_SPEECH_KEYWORDS):
            has_cv_speech = True
            break
    has_nlp = any(k in skills_found for k in NLP_KEYWORDS) or career_nlp_hits > 0
    if has_cv_speech and not has_nlp:
        disqualify_multiplier *= 0.1
        
    # Noida/Pune Location Score
    loc = profile.get("location", "").lower()
    country = profile.get("country", "").lower()
    relocate = signals.get("willing_to_relocate", False)
    
    loc_score = 10.0
    if "noida" in loc or "pune" in loc:
        loc_score = 100.0
    elif any(city in loc for city in ["delhi", "gurgaon", "hyderabad", "mumbai", "pune", "noida"]):
        loc_score = 80.0
    elif "bangalore" in loc or "bengaluru" in loc:
        loc_score = 60.0
    elif country == "india" or relocate:
        loc_score = 40.0
    else:
        loc_score = 10.0
        
    # Shipper vs Researcher keyword adjustments
    shipper_mult = 1.0 + 0.05 * min(6, shipper_hits)
    researcher_mult = 1.0 - 0.04 * min(8, researcher_hits)
    
    # 4. Behavioral Signals Modifiers
    behavior_mult = 1.0
    
    # Notice period
    notice = signals.get("notice_period_days", 90)
    if notice <= 30:
        behavior_mult *= 1.3
    elif notice <= 60:
        behavior_mult *= 1.1
    elif notice >= 90:
        behavior_mult *= 0.7
        
    # Recent activity
    last_act_s = signals.get("last_active_date")
    last_act = parse_date(last_act_s)
    if last_act:
        ref_date = datetime(2026, 7, 2)
        days_inactive = (ref_date - last_act).days
        if days_inactive <= 30:
            behavior_mult *= 1.2
        elif days_inactive <= 90:
            behavior_mult *= 1.0
        elif days_inactive <= 180:
            behavior_mult *= 0.8
        else:
            behavior_mult *= 0.5
            
    # Response rates
    resp_rate = signals.get("recruiter_response_rate", 0.5)
    if resp_rate >= 0.7:
        behavior_mult *= 1.2
    elif resp_rate < 0.2:
        behavior_mult *= 0.4
        
    # Profile completeness and verification
    if signals.get("open_to_work_flag"):
        behavior_mult *= 1.1
    if signals.get("verified_email") and signals.get("verified_phone"):
        behavior_mult *= 1.1
    if signals.get("linkedin_connected"):
        behavior_mult *= 1.05
        
    github = signals.get("github_activity_score", -1)
    if github > 50:
        behavior_mult *= 1.1
        
    # Composite Score
    base_score = (exp_score * 0.25 + skills_match_score * 0.65 + loc_score * 0.10)
    final_score = base_score * disqualify_multiplier * shipper_mult * researcher_mult * behavior_mult
    
    return final_score

def generate_reasoning(c, rank):
    profile = c.get("profile", {})
    skills = c.get("skills", [])
    career = c.get("career_history", [])
    signals = c.get("redrob_signals", {})
    cid = c.get("candidate_id", "CAND_0000000")
    
    # 1. Gather facts
    years_exp = profile.get("years_of_experience", 0.0)
    title = profile.get("current_title", "Software Engineer")
    company = profile.get("current_company", "Product Company")
    location = profile.get("location", "India")
    
    # Clean up non-ascii or arrows in current title/company
    title = title.replace("\u2192", "->").strip()
    company = company.replace("\u2192", "->").strip()
    
    # Find matching AI/NLP/Retrieval skills
    matching_skills = []
    for s in skills:
        sname = s.get("name", "")
        sname_lower = sname.lower()
        if any(k in sname_lower for k in NLP_KEYWORDS | VEC_KEYWORDS | EVAL_KEYWORDS):
            matching_skills.append(sname)
    
    top_skills = matching_skills[:3]
    skills_str = ", ".join(top_skills) if top_skills else "Python, Machine Learning"
    
    # Check notice period
    notice = signals.get("notice_period_days", 90)
    
    # Check location and relocation
    loc_lower = location.lower()
    in_hub = "noida" in loc_lower or "pune" in loc_lower
    relocate = signals.get("willing_to_relocate", False)
    
    # Check tenure and consulting
    avg_tenure = 0
    if len(career) > 1:
        total_duration = sum(job.get("duration_months", 0) for job in career)
        avg_tenure = total_duration / len(career)
        
    companies = [job.get("company", "").lower() for job in career if job.get("company")]
    all_consulting = all(any(c_firm in comp for c_firm in CONSULTING_COMPANIES) for comp in companies) if companies else False
    
    # Check management title
    is_management = False
    if career:
        recent_title = career[0].get("title", "").lower()
        recent_desc = career[0].get("description", "").lower()
        if any(mt in recent_title for mt in MANAGEMENT_TITLES):
            coding_words = {"code", "implement", "build", "develop", "train", "model", "pipeline", "deploy", "write"}
            if not any(cw in recent_desc for cw in coding_words):
                is_management = True

    # 2. Select template dynamically based on candidate ID to ensure variation
    cid_num = 0
    try:
        cid_num = int(cid.split("_")[1])
    except Exception:
        pass
    
    flow_idx = cid_num % 4
    
    # Opening sentence
    if flow_idx == 0:
        opening = f"{years_exp:.1f}y experience, currently {title} at {company}."
    elif flow_idx == 1:
        opening = f"Experienced {title} at {company} with a solid {years_exp:.1f}y career history."
    elif flow_idx == 2:
        opening = f"Brings {years_exp:.1f}y of applied software and ML experience, serving as {title} at {company}."
    else:
        opening = f"Solid fit in the {years_exp:.1f}y range, currently working as {title} at {company}."
        
    # Skills sentence
    if flow_idx == 0:
        skills_phrase = f"Demonstrates hands-on expertise in {skills_str} aligning with the search & retrieval focus."
    elif flow_idx == 1:
        skills_phrase = f"Strong background in {skills_str}, showing a product-oriented engineering approach."
    elif flow_idx == 2:
        skills_phrase = f"Proficient in {skills_str} with real-world implementation experience."
    else:
        skills_phrase = f"Technical depth includes {skills_str}, matching the JD's ranking/NLP stack."

    # Closing details
    closings = []
    
    # Location
    if in_hub:
        closings.append("Pune/Noida-based.")
    elif relocate:
        closings.append(f"Located in {location.split(',')[0]}, willing to relocate.")
    else:
        closings.append(f"Based in {location.split(',')[0]} (relocation status unclear).")
        
    # Notice period
    if notice <= 15:
        closings.append("Immediate availability (15-day notice).")
    elif notice <= 30:
        closings.append(f"Can join quickly ({notice}-day notice).")
    elif notice >= 90:
        closings.append(f"Note: long {notice}-day notice period.")
    else:
        closings.append(f"{notice}-day notice.")
        
    # Concerns
    concerns = []
    if all_consulting:
        concerns.append("consulting firms background only")
    if is_management:
        concerns.append("management-heavy focus")
    if avg_tenure > 0 and avg_tenure <= 18:
        concerns.append("history of short tenures")
        
    if concerns:
        closings.append(f"Potential concerns around {', '.join(concerns)}.")
        
    closing_str = " ".join(closings)
    
    reasoning = f"{opening} {skills_phrase} {closing_str}"
    
    # Strip any potential double spaces or weird unicode characters
    reasoning = " ".join(reasoning.split())
    return reasoning

def main():
    parser = argparse.ArgumentParser(description="Rank candidates for the Redrob AI challenge.")
    parser.add_argument("--candidates", required=True, help="Path to candidates.jsonl")
    parser.add_argument("--out", required=True, help="Path to output submission CSV")
    args = parser.parse_args()
    
    print(f"Reading candidates from {args.candidates}...")
    start_time = time.time()
    
    candidates_scores = []
    count = 0
    
    with open(args.candidates, "r", encoding="utf-8") as f:
        for line in f:
            count += 1
            c = json.loads(line)
            cid = c.get("candidate_id")
            if not cid:
                continue
            
            score = calculate_score(c)
            if score > 0:
                candidates_scores.append((cid, score, c))
                
            if count % 20000 == 0:
                print(f"Processed {count} candidates... (time: {time.time() - start_time:.2f}s)")
                
    print(f"Finished processing {count} records in {time.time() - start_time:.2f}s.")
    print(f"Found {len(candidates_scores)} candidates with non-zero scores.")
    
    # Sort candidates
    # Primary sort: score descending
    # Secondary sort: candidate_id ascending (tie break rule)
    candidates_scores.sort(key=lambda x: (-x[1], x[0]))
    
    # Select top 100
    top_100 = candidates_scores[:100]
    
    # Write to CSV
    print(f"Writing top 100 candidates to {args.out}...")
    with open(args.out, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["candidate_id", "rank", "score", "reasoning"])
        
        for idx, (cid, score, c) in enumerate(top_100):
            rank = idx + 1
            reasoning = generate_reasoning(c, rank)
            writer.writerow([cid, rank, round(score, 4), reasoning])
            
    print("CSV generated successfully.")

if __name__ == "__main__":
    main()
