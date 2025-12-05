import React from 'react';

const ProfessionalPage = () => {
  return (
    <div className="w-full h-full overflow-y-auto bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white p-8">
      {/* Header Section */}
      <div className="max-w-7xl mx-auto">
        {/* Hero Section */}
        <div className="mb-16 text-center">
          <div className="inline-block px-4 py-2 mb-4 rounded-full bg-cyan-500/20 border border-cyan-500/30 backdrop-blur-sm">
            <span className="text-cyan-400 text-sm font-mono tracking-wider">PROFESSIONAL PORTFOLIO</span>
          </div>
          
          <h1 className="text-5xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 bg-clip-text text-transparent">
            Michael Gauthier Guillet
          </h1>
          
          <p className="text-xl md:text-2xl text-gray-300 font-light mb-4">
            Manufacturing Engineer • AI Developer • VPO Specialist
          </p>
          
          <div className="flex justify-center gap-4 text-sm text-gray-400">
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
              AB InBev Facility
            </span>
            <span>•</span>
            <span>KeelClip Expert</span>
            <span>•</span>
            <span>Québec, Canada</span>
          </div>
        </div>

        {/* Main Product: KeelClip VPO Analyzer */}
        <div className="mb-16 bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700 rounded-2xl p-8 md:p-12 backdrop-blur-sm">
          <div className="grid md:grid-cols-2 gap-12">
            <div>
              <div className="inline-block px-3 py-1 mb-4 rounded-md bg-blue-500/20 border border-blue-500/30">
                <span className="text-blue-400 text-xs font-mono">FLAGSHIP PRODUCT</span>
              </div>
              
              <h2 className="text-4xl font-bold mb-4 bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                KeelClip VPO Analyzer
              </h2>
              
              <p className="text-gray-300 text-lg mb-6 leading-relaxed">
                AI-powered 5-Why incident report generator for KeelClip packaging machines. 
                Transforms 45 minutes of manual work into 2 minutes of automated, VPO-compliant analysis.
              </p>

              <div className="space-y-4 mb-8">
                <div className="flex items-start gap-3">
                  <div className="w-6 h-6 rounded-full bg-green-500/20 border border-green-500/30 flex items-center justify-center flex-shrink-0 mt-1">
                    <span className="text-green-400 text-xs">✓</span>
                  </div>
                  <div>
                    <h4 className="font-semibold text-white mb-1">96% Time Savings</h4>
                    <p className="text-gray-400 text-sm">Reduces report generation from 45 minutes to 2 minutes</p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-6 h-6 rounded-full bg-green-500/20 border border-green-500/30 flex items-center justify-center flex-shrink-0 mt-1">
                    <span className="text-green-400 text-xs">✓</span>
                  </div>
                  <div>
                    <h4 className="font-semibold text-white mb-1">100% VPO Compliance</h4>
                    <p className="text-gray-400 text-sm">Guaranteed audit-proof reports following AB InBev standards</p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-6 h-6 rounded-full bg-green-500/20 border border-green-500/30 flex items-center justify-center flex-shrink-0 mt-1">
                    <span className="text-green-400 text-xs">✓</span>
                  </div>
                  <div>
                    <h4 className="font-semibold text-white mb-1">AI Vision Analysis</h4>
                    <p className="text-gray-400 text-sm">Automatically identifies components, defects, and root causes</p>
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap gap-4">
                <a 
                  href="/keelclip-vpo-analyzer/sales-page.html" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="px-6 py-3 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold transition-all duration-300 transform hover:scale-105 shadow-lg hover:shadow-cyan-500/50"
                >
                  Voir la Brochure →
                </a>
                <button className="px-6 py-3 rounded-lg border-2 border-gray-600 hover:border-cyan-400 text-gray-300 hover:text-white font-semibold transition-all duration-300">
                  Demander une Démo
                </button>
              </div>
            </div>

            {/* Statistics & Metrics */}
            <div className="space-y-6">
              <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
                <div className="grid grid-cols-2 gap-6">
                  <div>
                    <div className="text-3xl font-bold text-cyan-400 mb-1">$299</div>
                    <div className="text-sm text-gray-400">per month</div>
                  </div>
                  <div>
                    <div className="text-3xl font-bold text-blue-400 mb-1">$4,999</div>
                    <div className="text-sm text-gray-400">perpetual license</div>
                  </div>
                  <div>
                    <div className="text-3xl font-bold text-purple-400 mb-1">2,000+</div>
                    <div className="text-sm text-gray-400">target facilities</div>
                  </div>
                  <div>
                    <div className="text-3xl font-bold text-green-400 mb-1">100%</div>
                    <div className="text-sm text-gray-400">VPO compliance</div>
                  </div>
                </div>
              </div>

              <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
                <h4 className="font-semibold text-white mb-4">Technology Stack</h4>
                <div className="flex flex-wrap gap-2">
                  {['Llama 3.2 Vision', 'Node.js', 'AnythingLLM', 'VPO Standards', 'Ollama', 'React'].map((tech) => (
                    <span key={tech} className="px-3 py-1 rounded-full bg-gray-700/50 border border-gray-600 text-gray-300 text-xs">
                      {tech}
                    </span>
                  ))}
                </div>
              </div>

              <div className="bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
                  <h4 className="font-semibold text-white">Status: In Development</h4>
                </div>
                <p className="text-sm text-gray-300">
                  Seeking $40k seed funding. Beta product functional. Target launch: Q1 2026.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Professional Experience */}
        <div className="mb-16">
          <h2 className="text-3xl font-bold mb-8 text-center">
            <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Professional Experience
            </span>
          </h2>

          <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-8">
            <div className="flex items-start gap-6">
              <div className="w-16 h-16 rounded-lg bg-gradient-to-br from-red-600 to-red-800 flex items-center justify-center flex-shrink-0">
                <span className="text-white font-bold text-2xl">AB</span>
              </div>
              <div className="flex-grow">
                <h3 className="text-2xl font-bold text-white mb-2">Manufacturing Operator</h3>
                <div className="text-cyan-400 font-mono text-sm mb-4">AB InBev Packaging Facility • Québec, Canada</div>
                <div className="text-gray-400 space-y-2">
                  <p>• KeelClip packaging machine operator and technical specialist</p>
                  <p>• VPO (Value Practices & Operations) methodology expert</p>
                  <p>• Root Cause Analysis (RCA) and 5-Why report specialist</p>
                  <p>• Identified $50k+/year efficiency improvement opportunity through AI automation</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Skills & Expertise */}
        <div className="mb-16">
          <h2 className="text-3xl font-bold mb-8 text-center">
            <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Expertise
            </span>
          </h2>

          <div className="grid md:grid-cols-3 gap-6">
            <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-6 hover:border-cyan-500/50 transition-all duration-300">
              <div className="text-cyan-400 text-3xl mb-4">🏭</div>
              <h3 className="text-xl font-bold text-white mb-3">Manufacturing</h3>
              <ul className="text-gray-400 space-y-2 text-sm">
                <li>• VPO/WCM Methodology</li>
                <li>• KeelClip Machines (Graphic Packaging)</li>
                <li>• Root Cause Analysis (5-Why)</li>
                <li>• Quality Management Systems</li>
              </ul>
            </div>

            <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-6 hover:border-cyan-500/50 transition-all duration-300">
              <div className="text-blue-400 text-3xl mb-4">🤖</div>
              <h3 className="text-xl font-bold text-white mb-3">AI & Development</h3>
              <ul className="text-gray-400 space-y-2 text-sm">
                <li>• Computer Vision (LLaMA, Qwen)</li>
                <li>• Full-Stack Development</li>
                <li>• Node.js / React / Express</li>
                <li>• Local AI (Ollama, AnythingLLM)</li>
              </ul>
            </div>

            <div className="bg-gray-800/30 border border-gray-700 rounded-xl p-6 hover:border-cyan-500/50 transition-all duration-300">
              <div className="text-purple-400 text-3xl mb-4">💼</div>
              <h3 className="text-xl font-bold text-white mb-3">Business</h3>
              <ul className="text-gray-400 space-y-2 text-sm">
                <li>• Product Development</li>
                <li>• B2B SaaS Strategy</li>
                <li>• Startup Fundraising</li>
                <li>• Technical Writing</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Contact CTA */}
        <div className="text-center bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700 rounded-2xl p-12">
          <h2 className="text-3xl font-bold mb-4 text-white">Interested in Collaboration?</h2>
          <p className="text-gray-300 mb-8 max-w-2xl mx-auto">
            Looking for investors, partners, or beta customers for KeelClip VPO Analyzer. 
            Also available for manufacturing consulting and AI implementation projects.
          </p>
          <div className="flex justify-center gap-4 flex-wrap">
            <a 
              href="mailto:mgauthierguillet@gmail.com" 
              className="px-8 py-4 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold transition-all duration-300 transform hover:scale-105 shadow-lg hover:shadow-cyan-500/50"
            >
              Contact Me
            </a>
            <a 
              href="https://www.linkedin.com/in/yourprofile" 
              target="_blank" 
              rel="noopener noreferrer"
              className="px-8 py-4 rounded-lg border-2 border-gray-600 hover:border-cyan-400 text-gray-300 hover:text-white font-semibold transition-all duration-300"
            >
              LinkedIn
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProfessionalPage;
