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
                          
    # Skill assessment scores bonus (platform activity check)
    skill_scores = signals.get("skill_assessment_scores", {})
    assessment_bonus = 0.0
    for sname, score in skill_scores.items():
        sname_lower = sname.lower()
        if any(k in sname_lower for k in NLP_KEYWORDS | VEC_KEYWORDS | EVAL_KEYWORDS):
            if score >= 80:
                assessment_bonus += (score - 70) * 1.5  # up to 45 points per skill
            elif score >= 60:
                assessment_bonus += (score - 50) * 0.5  # up to 5 points
    skills_match_score += assessment_bonus

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

    # Interview completion rate
    icr = signals.get("interview_completion_rate", 1.0)
    if icr >= 0.8:
        behavior_mult *= 1.2
    elif icr < 0.4:
        behavior_mult *= 0.6

    # Offer acceptance rate
    oar = signals.get("offer_acceptance_rate", -1.0)
    if oar > 0.7:
        behavior_mult *= 1.15
    elif oar == 0.0:
        behavior_mult *= 0.9

    # Saved by recruiters 30d
    saved_count = signals.get("saved_by_recruiters_30d", 0)
    if saved_count >= 3:
        behavior_mult *= 1.1
    elif saved_count == 0:
        behavior_mult *= 0.95

    # Profile completeness score
    pcs = signals.get("profile_completeness_score", 100.0)
    if pcs >= 85:
        behavior_mult *= 1.1
    elif pcs < 50:
        behavior_mult *= 0.8

    # Average response time
    art = signals.get("avg_response_time_hours", 24.0)
    if art <= 4:
        behavior_mult *= 1.1
    elif art >= 48:
        behavior_mult *= 0.8

    # Connection count
    conn_count = signals.get("connection_count", 0)
    if conn_count > 100:
        behavior_mult *= 1.05

    # Popularity signals (profile views / search appearance)
    pvr = signals.get("profile_views_received_30d", 0)
    sa30 = signals.get("search_appearance_30d", 0)
    if pvr >= 20 or sa30 >= 50:
        behavior_mult *= 1.05
        
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
    title = profile.get("current_title", "Software Engineer").strip()
    company = profile.get("current_company", "Product Company").strip()
    location = profile.get("location", "India").strip()
    
    # Clean up non-ascii or arrows in current title/company
    title = title.replace("\u2192", "->").replace("  ", " ").strip()
    company = company.replace("\u2192", "->").replace("  ", " ").strip()
    
    # Find matching AI/NLP/Retrieval skills
    matching_skills = []
    for s in skills:
        sname = s.get("name", "")
        sname_lower = sname.lower()
        if any(k in sname_lower for k in NLP_KEYWORDS | VEC_KEYWORDS | EVAL_KEYWORDS):
            matching_skills.append(sname)
    
    top_skills = matching_skills[:3]
    skills_str = ", ".join(top_skills) if top_skills else ""
    
    # Determine candidate's core focus area
    nlp_skills = [s for s in matching_skills if any(k in s.lower() for k in NLP_KEYWORDS)]
    vec_skills = [s for s in matching_skills if any(k in s.lower() for k in VEC_KEYWORDS)]
    eval_skills = [s for s in matching_skills if any(k in s.lower() for k in EVAL_KEYWORDS)]
    
    focus = "general software/ML"
    if vec_skills:
        focus = f"vector search/retrieval ({vec_skills[0]})"
    elif nlp_skills:
        focus = f"NLP and LLMs ({nlp_skills[0]})"
    elif eval_skills:
        focus = f"retrieval evaluation metrics ({eval_skills[0]})"
        
    notice = signals.get("notice_period_days", 90)
    relocate = signals.get("willing_to_relocate", False)
    resp_rate = signals.get("recruiter_response_rate", 0.5)
    gh_score = signals.get("github_activity_score", -1)
    
    # Check location
    loc_lower = location.lower()
    in_hub = "noida" in loc_lower or "pune" in loc_lower
    
    # Gather concerns
    concerns = []
    avg_tenure = 0
    if len(career) > 1:
        total_duration = sum(job.get("duration_months", 0) for job in career)
        avg_tenure = total_duration / len(career)
        
    companies = [job.get("company", "").lower() for job in career if job.get("company")]
    all_consulting = all(any(c_firm in comp for c_firm in CONSULTING_COMPANIES) for comp in companies) if companies else False
    
    if all_consulting:
        concerns.append("consulting background")
    if avg_tenure > 0 and avg_tenure <= 18:
        concerns.append("job hopping / short tenures")
    if notice >= 90:
        concerns.append(f"{notice}-day notice period")
    if resp_rate < 0.3:
        concerns.append("low response rate")
        
    # Generate based on rank tier
    if rank <= 15:
        # Tier 1: Stellar matches (Top 15)
        openings = [
            f"Stellar candidate with {years_exp:.1f}y experience, currently {title} at {company}.",
            f"Top-tier {title} at {company} with {years_exp:.1f}y of relevant ML/search experience.",
            f"Highly qualified candidate with {years_exp:.1f}y experience, currently serving as {title} at {company}."
        ]
        opening = openings[rank % len(openings)]
        
        skills_phrases = [
            f"Demonstrates deep expertise in {skills_str or 'NLP'}, aligning perfectly with the JD's search and retrieval focus.",
            f"Proven engineering capability in {focus}, critical for scaling the search infrastructure.",
            f"Brings strong hands-on experience in {skills_str or 'vector search'}, showing excellent product-focused ML depth."
        ]
        skills_phrase = skills_phrases[rank % len(skills_phrases)]
        
        closings = []
        if in_hub:
            closings.append("Ideally located in the Noida/Pune hiring hub.")
        elif relocate:
            closings.append(f"Based in {location.split(',')[0]} but willing to relocate.")
        else:
            closings.append(f"Located in {location.split(',')[0]}.")
            
        if notice <= 30:
            closings.append(f"Highly hireable with a quick {notice}-day notice.")
        else:
            closings.append(f"Note: {notice}-day notice period.")
            
        if resp_rate >= 0.8:
            closings.append(f"Excellent response rate of {resp_rate*100:.0f}% indicates strong candidate engagement.")
        if gh_score > 60:
            closings.append(f"Strong GitHub activity score ({gh_score}) demonstrates active engineering contributions.")
            
        closing_str = " ".join(closings)
        reasoning = f"{opening} {skills_phrase} {closing_str}"
        
    elif rank <= 75:
        # Tier 2: Mid-tier matches (Ranks 16-75)
        openings = [
            f"Experienced {title} with {years_exp:.1f}y tenure, currently at {company}.",
            f"Solid background of {years_exp:.1f}y in engineering, working as {title} at {company}.",
            f"Candidate brings {years_exp:.1f}y of software experience, currently {title} at {company}."
        ]
        opening = openings[rank % len(openings)]
        
        skills_phrases = [
            f"Shows good skills alignment with experience in {skills_str or focus}.",
            f"Has relevant background in {skills_str or 'NLP and retrieval'}, matching the technical requirements of the role.",
            f"Familiar with {focus}, representing a good technical match for the search team."
        ]
        skills_phrase = skills_phrases[rank % len(skills_phrases)]
        
        closings = []
        if in_hub:
            closings.append("Pune/Noida-based.")
        elif relocate:
            closings.append(f"Located in {location.split(',')[0]}, open to relocation.")
        else:
            closings.append(f"Based in {location.split(',')[0]}.")
            
        if notice <= 30:
            closings.append(f"Available relatively quickly ({notice}-day notice).")
        else:
            closings.append(f"Standard {notice}-day notice period.")
            
        if concerns:
            closings.append(f"Minor concerns include {', '.join(concerns[:2])}.")
            
        closing_str = " ".join(closings)
        reasoning = f"{opening} {skills_phrase} {closing_str}"
        
    else:
        # Tier 3: Bottom-tier matches (Ranks 76-100)
        openings = [
            f"Adjacent profile at rank {rank} with {years_exp:.1f}y experience as {title} at {company}.",
            f"Marginal fit with {years_exp:.1f}y of experience, currently working as {title} at {company}.",
            f"Lighter alignment on search specific skills, currently {title} at {company} ({years_exp:.1f}y exp)."
        ]
        opening = openings[rank % len(openings)]
        
        skills_phrases = [
            f"Brings limited exposure to {skills_str or 'relevant AI skills'}, representing a skills gap.",
            f"Technical skills in {skills_str or 'general software'} do not fully align with the retrieval focus of the JD.",
            f"Shows basic familiarity with {focus} but lacks hands-on scale/retrieval experience."
        ]
        skills_phrase = skills_phrases[rank % len(skills_phrases)]
        
        closings = []
        if concerns:
            closings.append(f"Significant concerns: {', '.join(concerns)}.")
        else:
            closings.append("Lacks direct product or search engineering experience.")
            
        if in_hub:
            closings.append("Located in hub.")
        else:
            closings.append(f"Located in {location.split(',')[0]}.")
            
        closings.append(f"Response rate is {resp_rate*100:.0f}%.")
        
        closing_str = " ".join(closings)
        reasoning = f"{opening} {skills_phrase} {closing_str}"
        
    # Strip any potential double spaces
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
    
    # Normalize scores to [0.0, 1.0] range and round to 4 decimal places
    normalized_candidates = []
    if candidates_scores:
        max_score = candidates_scores[0][1] # Candidates are sorted, first element has the max score
        if max_score > 0:
            for cid, score, c in candidates_scores:
                rounded_score = round(score / max_score, 4)
                normalized_candidates.append((cid, rounded_score, c))
        else:
            for cid, score, c in candidates_scores:
                normalized_candidates.append((cid, 0.0, c))
    else:
        normalized_candidates = candidates_scores
        
    # Re-sort to resolve tie breaks after rounding
    normalized_candidates.sort(key=lambda x: (-x[1], x[0]))
        
    # Select top 100
    top_100 = normalized_candidates[:100]
    
    # Write to CSV
    print(f"Writing top 100 candidates to {args.out}...")
    with open(args.out, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["candidate_id", "rank", "score", "reasoning"])
        
        for idx, (cid, score, c) in enumerate(top_100):
            rank = idx + 1
            reasoning = generate_reasoning(c, rank)
            writer.writerow([cid, rank, score, reasoning])
            
    print("CSV generated successfully.")

if __name__ == "__main__":
    main()
