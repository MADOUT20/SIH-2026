"use client"

import { useState } from "react"
import {
  UploadCloud,
  FileText,
  AlertCircle,
  CheckCircle2,
  Loader2,
  Sparkles,
  TrendingUp,
  Layers,
  ShieldAlert,
  SearchCheck,
  BrainCircuit,
  FileCode,
  ArrowRight
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { uploadTrafficFile, processSampleDemoFile, type FileUploadAnalysisResponse } from "@/lib/api"
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from "recharts"

export default function WorkbenchPage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [isUploading, setIsUploading] = useState(false)
  const [uploadError, setUploadError] = useState("")
  const [analysisResult, setAnalysisResult] = useState<(FileUploadAnalysisResponse & { is_demo?: boolean; origin?: string }) | null>(null)
  const [dragActive, setDragActive] = useState(false)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0])
      setUploadError("")
    }
  }

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true)
    } else if (e.type === "dragleave") {
      setDragActive(false)
    }
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0]
      const ext = file.name.split('.').pop()?.toLowerCase()
      if (ext === 'pcap' || ext === 'pcapng' || ext === 'csv') {
        setSelectedFile(file)
        setUploadError("")
      } else {
        setUploadError("Invalid file type. Please upload a .pcap, .pcapng, or .csv file.")
      }
    }
  }

  const handleUpload = async (fileToUpload?: File) => {
    const file = fileToUpload || selectedFile
    if (!file) return

    setIsUploading(true)
    setUploadError("")

    try {
      const result = await uploadTrafficFile(file)
      setAnalysisResult(result)
    } catch (err: any) {
      console.error("Offline file analysis failed:", err)
      setUploadError(err.message || "Failed to process offline traffic file. Make sure backend is running.")
    } finally {
      setIsUploading(false)
    }
  }

  const handleRunSampleDemo = async (type: "pcap" | "csv") => {
    setIsUploading(true)
    setUploadError("")

    try {
      const result = await processSampleDemoFile(type)
      setAnalysisResult(result)
    } catch (err: any) {
      console.error("Sample demo analysis failed:", err)
      setUploadError(err.message || "Failed to run sample demo analysis.")
    } finally {
      setIsUploading(false)
    }
  }

  const handleRunSampleCSV = () => handleRunSampleDemo("csv")
  const handlerRunSampleCSV = handleRunSampleCSV


  const forecastData = analysisResult?.forecast?.forecast?.map((item) => ({
    step: `Step t+${item.step}`,
    probability: Math.round(item.probability * 100),
  })) || []

  const currentProb = analysisResult?.forecast?.current_probability != null
    ? Math.round(analysisResult.forecast.current_probability * 100)
    : 0

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col justify-between gap-4 rounded-xl border bg-card p-6 shadow-sm sm:flex-row sm:items-center">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="border-sky-500/30 text-sky-500 bg-sky-500/10">
              Offline Traffic Analysis
            </Badge>
            <Badge variant="secondary">PyTorch LSTM World Model</Badge>
          </div>
          <h1 className="text-2xl font-bold tracking-tight">PCAP & CSV File Inspection Workbench</h1>
          <p className="text-sm text-muted-foreground">
            Ingest offline network traffic captures (.pcap, .pcapng, .csv), extract 27 canonical flow features, and evaluate 5-step forward attack forecasting with MITRE stage mapping.
          </p>
        </div>
        <Button onClick={handleRunSampleCSV} disabled={isUploading} variant="outline" className="gap-2 border-sky-500/30 hover:bg-sky-500/10">
          <Sparkles className="h-4 w-4 text-sky-500" />
          Test Sample Capture
        </Button>
      </div>

      {/* File Upload Dropzone */}
      <Card className="border-dashed border-2 transition-all">
        <CardContent className="p-8">
          <form
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onSubmit={(e) => {
              e.preventDefault()
              handleUpload()
            }}
            className="flex flex-col items-center justify-center space-y-4 text-center"
          >
            <div className={`rounded-full p-4 transition-colors ${dragActive ? "bg-sky-500/20 text-sky-400" : "bg-muted text-muted-foreground"}`}>
              <UploadCloud className="h-10 w-10" />
            </div>

            <div className="space-y-1">
              <h3 className="text-lg font-semibold">Upload PCAP or CSV Capture File</h3>
              <p className="text-sm text-muted-foreground">
                Drag and drop your network traffic file here, or click to browse. Supports <span className="font-semibold text-foreground">.pcap</span>, <span className="font-semibold text-foreground">.pcapng</span>, or <span className="font-semibold text-foreground">.csv</span> files.
              </p>
            </div>

            <input
              id="file-upload"
              type="file"
              accept=".pcap,.pcapng,.csv"
              onChange={handleFileChange}
              className="hidden"
            />

            <div className="flex flex-wrap items-center justify-center gap-3">
              <label htmlFor="file-upload">
                <Button type="button" variant="outline" className="cursor-pointer gap-2" asChild>
                  <span>
                    <FileCode className="h-4 w-4" />
                    Browse Computer
                  </span>
                </Button>
              </label>

              <Button type="submit" disabled={!selectedFile || isUploading} className="gap-2 bg-sky-600 hover:bg-sky-500 text-white">
                {isUploading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Analyzing Traffic Flows...
                  </>
                ) : (
                  <>
                    <SearchCheck className="h-4 w-4" />
                    Run World Model Forecast
                  </>
                )}
              </Button>

              <div className="w-full flex flex-wrap items-center justify-center gap-2 pt-3 border-t border-border mt-2">
                <span className="text-xs text-muted-foreground font-medium">DEMO FIXTURES:</span>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => handleRunSampleDemo("pcap")}
                  disabled={isUploading}
                  className="h-7 text-xs bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/30 hover:bg-purple-500/20 font-semibold"
                >
                  🟣 Load Sample PCAP (Demo)
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => handleRunSampleDemo("csv")}
                  disabled={isUploading}
                  className="h-7 text-xs bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30 hover:bg-amber-500/20 font-semibold"
                >
                  🟡 Load Sample CSV (Demo)
                </Button>
              </div>
            </div>

            {selectedFile && (
              <div className="flex items-center gap-2 rounded-md bg-muted px-3 py-1.5 text-xs font-medium">
                <FileText className="h-4 w-4 text-sky-500" />
                <span>{selectedFile.name}</span>
                <span className="text-muted-foreground">({(selectedFile.size / 1024).toFixed(1)} KB)</span>
              </div>
            )}

            {uploadError && (
              <div className="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-xs font-medium text-destructive">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{uploadError}</span>
              </div>
            )}
          </form>
        </CardContent>
      </Card>

      {/* Analysis Results Display */}
      {analysisResult && (
        <div className="space-y-6">
          {/* File Summary Cards */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between gap-1">
                  <CardDescription>File Ingested</CardDescription>
                  <Badge variant="outline" className={analysisResult.is_demo ? "bg-amber-500/10 text-amber-500 border-amber-500/30 font-bold text-[10px]" : "bg-emerald-500/10 text-emerald-500 border-emerald-500/30 font-bold text-[10px]"}>
                    {analysisResult.origin || (analysisResult.is_demo ? "DEMO SAMPLE ANALYSIS" : "USER FILE ANALYSIS")}
                  </Badge>
                </div>
                <CardTitle className="text-lg font-semibold truncate">{analysisResult.filename}</CardTitle>
              </CardHeader>
              <CardContent className="text-xs text-muted-foreground flex justify-between items-center">
                <Badge variant="outline">{analysisResult.file_type}</Badge>
                <span>{(analysisResult.file_size_bytes / 1024).toFixed(1)} KB</span>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Flows Extracted</CardDescription>
                <CardTitle className="text-2xl font-bold">{analysisResult.flows_extracted}</CardTitle>
              </CardHeader>
              <CardContent className="text-xs text-muted-foreground">
                27-Dimensional Flow Vectors
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Temporal Window</CardDescription>
                <CardTitle className="text-2xl font-bold">{analysisResult.window_states} States</CardTitle>
              </CardHeader>
              <CardContent className="text-xs text-muted-foreground">
                5-Sec State Aggregation Window
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Attack Probability</CardDescription>
                <CardTitle className={`text-2xl font-bold ${currentProb > 70 ? "text-destructive" : currentProb > 40 ? "text-amber-500" : "text-emerald-500"}`}>
                  {currentProb}%
                </CardTitle>
              </CardHeader>
              <CardContent className="text-xs text-muted-foreground">
                PyTorch LSTM Current Score
              </CardContent>
            </Card>
          </div>

          {/* Main ML Forecast & MITRE Grid */}
          <div className="grid gap-6 lg:grid-cols-3">
            {/* 5-Step Forecast Timeline Chart */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <TrendingUp className="h-5 w-5 text-sky-500" />
                      5-Step Forward Infiltration Trajectory
                    </CardTitle>
                    <CardDescription>Multi-Horizon attack forecasting timeline computed by World Model</CardDescription>
                  </div>
                  <Badge className={currentProb > 70 ? "bg-destructive" : "bg-emerald-600"}>
                    {analysisResult.forecast?.predicted_stage || "Normal / Benign"}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={forecastData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                      <defs>
                        <linearGradient id="colorProb" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#0284c7" stopOpacity={0.8}/>
                          <stop offset="95%" stopColor="#0284c7" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                      <XAxis dataKey="step" stroke="#888888" fontSize={12} />
                      <YAxis domain={[0, 100]} stroke="#888888" fontSize={12} unit="%" />
                      <Tooltip formatter={(value: number) => [`${value}%`, 'Infiltration Prob']} />
                      <Area type="monotone" dataKey="probability" stroke="#0284c7" fillOpacity={1} fill="url(#colorProb)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>

                <div className="mt-4 grid grid-cols-5 gap-2 text-center text-xs">
                  {forecastData.map((item, i) => (
                    <div key={i} className="rounded bg-muted p-2">
                      <div className="font-semibold text-muted-foreground">{item.step}</div>
                      <div className="text-sm font-bold text-sky-500">{item.probability}%</div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* MITRE Stage & Explainability Panel */}
            <Card className="space-y-4">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <BrainCircuit className="h-5 w-5 text-sky-500" />
                  MITRE Stage & Attribution
                </CardTitle>
                <CardDescription>Explainability feature attributions driving prediction</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="rounded-lg border bg-muted/50 p-4 space-y-2">
                  <span className="text-xs font-medium text-muted-foreground">Predicted MITRE ATT&CK Stage</span>
                  <div className="text-base font-bold text-sky-500">
                    {analysisResult.forecast?.predicted_stage}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Stage Confidence: {Math.round((analysisResult.forecast?.stage_confidence || 0) * 100)}%
                  </div>
                </div>

                <div className="space-y-3">
                  <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Top 6 Feature Attributions</span>
                  {analysisResult.forecast?.top_features?.map((attr, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex justify-between text-xs font-medium">
                        <span>{attr.feature}</span>
                        <span className="text-sky-500">{(attr.importance * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={attr.importance * 100} className="h-1.5" />
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </div>
  )
}
