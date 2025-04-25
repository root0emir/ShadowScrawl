#!/usr/bin/env python3

import os
import json
import logging
import webbrowser
from typing import Dict, List, Set, Any, Optional
from datetime import datetime

from shadowscrawler.modules.color import color
from shadowscrawler.modules.linktree import LinkTree


class GraphVisualizer:
    """
    Creates interactive network graph visualizations of link relationships
    using D3.js for better analysis and exploration of crawled data.
    """

    def __init__(self, output_dir: str = "visualizations"):
        """
        Initialize the GraphVisualizer.
        
        Args:
            output_dir (str, optional): Directory to save visualizations. Defaults to "visualizations".
        """
        self.logger = logging.getLogger(__name__)
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.logger.info("Graph Visualizer initialized")
        
        # Template for HTML visualization
        self.html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowScrawl - Link Relationship Visualization</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #121212;
            color: #e0e0e0;
        }
        .container {
            width: 100%;
            height: 100vh;
            overflow: hidden;
        }
        #graph {
            width: 100%;
            height: 100%;
            position: relative;
        }
        .header {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background-color: rgba(18, 18, 18, 0.9);
            color: #e0e0e0;
            padding: 10px 20px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.5);
            z-index: 100;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
            color: #8c52ff;
        }
        .controls {
            position: fixed;
            top: 60px;
            right: 20px;
            background-color: rgba(34, 34, 34, 0.9);
            border-radius: 5px;
            padding: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
            z-index: 100;
        }
        .controls button {
            background-color: #8c52ff;
            color: white;
            border: none;
            padding: 8px 12px;
            margin: 5px;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        .controls button:hover {
            background-color: #6e3cbd;
        }
        .tooltip {
            position: absolute;
            background-color: rgba(34, 34, 34, 0.9);
            color: #e0e0e0;
            padding: 10px;
            border-radius: 4px;
            font-size: 14px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
            pointer-events: none;
            z-index: 200;
            max-width: 300px;
            opacity: 0;
            transition: opacity 0.3s;
        }
        .tooltip .url {
            color: #8c52ff;
            word-break: break-all;
        }
        .node {
            cursor: pointer;
        }
        .link {
            stroke: rgba(140, 82, 255, 0.3);
            stroke-width: 1.5px;
        }
        .info-panel {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background-color: rgba(34, 34, 34, 0.9);
            color: #e0e0e0;
            padding: 10px 20px;
            box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.3);
            transform: translateY(100%);
            transition: transform 0.3s;
            z-index: 100;
            max-height: 30vh;
            overflow-y: auto;
        }
        .info-panel.visible {
            transform: translateY(0);
        }
        .info-title {
            margin: 0 0 10px 0;
            color: #8c52ff;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ShadowScrawl Network Visualization</h1>
            <div>
                <span id="stats"></span>
            </div>
        </div>
        
        <div class="controls">
            <button id="zoom-in">Zoom In</button>
            <button id="zoom-out">Zoom Out</button>
            <button id="reset">Reset</button>
            <button id="toggle-physics">Toggle Physics</button>
            <button id="export-png">Export PNG</button>
        </div>
        
        <div id="graph"></div>
        
        <div class="tooltip" id="tooltip"></div>
        
        <div class="info-panel" id="info-panel">
            <h3 class="info-title">Node Information</h3>
            <div id="info-content"></div>
        </div>
    </div>

    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script>
        const graphData = GRAPH_DATA_PLACEHOLDER;
        
        // Set up the visualization
        const width = window.innerWidth;
        const height = window.innerHeight;
        
        // Create the SVG element
        const svg = d3.select("#graph")
            .append("svg")
            .attr("width", width)
            .attr("height", height)
            .attr("viewBox", [0, 0, width, height]);
            
        // Create a group for the graph
        const g = svg.append("g");
            
        // Create the simulation
        const simulation = d3.forceSimulation(graphData.nodes)
            .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(100))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collide", d3.forceCollide().radius(30));
            
        // Create the links
        const link = g.append("g")
            .selectAll("line")
            .data(graphData.links)
            .join("line")
            .attr("class", "link");
            
        // Create the nodes
        const node = g.append("g")
            .selectAll("circle")
            .data(graphData.nodes)
            .join("circle")
            .attr("class", "node")
            .attr("r", d => d.root ? 15 : (d.internal ? 8 : 5))
            .attr("fill", d => d.root ? "#ff5252" : (d.internal ? "#8c52ff" : "#4caf50"))
            .call(drag(simulation));
            
        // Add titles to nodes
        node.append("title")
            .text(d => d.id);
            
        // Set up the tooltip
        const tooltip = d3.select("#tooltip");
        
        node.on("mouseover", function(event, d) {
            const [x, y] = d3.pointer(event, this);
            tooltip.style("opacity", 1)
                .html(`
                    <div><strong>${d.name || 'Unknown'}</strong></div>
                    <div class="url">${d.id}</div>
                    <div>Status: ${d.status || 'Unknown'}</div>
                `)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            tooltip.style("opacity", 0);
        })
        .on("click", function(event, d) {
            // Show detailed information in the panel
            const infoPanel = document.getElementById("info-panel");
            const infoContent = document.getElementById("info-content");
            
            infoContent.innerHTML = `
                <p><strong>URL:</strong> ${d.id}</p>
                <p><strong>Title:</strong> ${d.name || 'Unknown'}</p>
                <p><strong>Status:</strong> ${d.status || 'Unknown'}</p>
                <p><strong>Internal:</strong> ${d.internal ? 'Yes' : 'No'}</p>
                <p><strong>Root:</strong> ${d.root ? 'Yes' : 'No'}</p>
                <p><strong>Links:</strong> ${d.linkCount || 0}</p>
            `;
            
            infoPanel.classList.add("visible");
            
            // Prevent event propagation
            event.stopPropagation();
        });
        
        // Update the simulation on each tick
        simulation.on("tick", () => {
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
                
            node
                .attr("cx", d => d.x)
                .attr("cy", d => d.y);
        });
        
        // Zoom functionality
        const zoom = d3.zoom()
            .scaleExtent([0.1, 10])
            .on("zoom", (event) => {
                g.attr("transform", event.transform);
            });
            
        svg.call(zoom);
        
        // Update stats
        document.getElementById("stats").textContent = `Nodes: ${graphData.nodes.length} | Links: ${graphData.links.length}`;
        
        // Hide the info panel when clicking outside
        document.addEventListener("click", function(event) {
            if (!event.target.closest(".node") && !event.target.closest("#info-panel")) {
                document.getElementById("info-panel").classList.remove("visible");
            }
        });
        
        // Control buttons
        document.getElementById("zoom-in").addEventListener("click", function() {
            svg.transition().call(zoom.scaleBy, 1.5);
        });
        
        document.getElementById("zoom-out").addEventListener("click", function() {
            svg.transition().call(zoom.scaleBy, 0.75);
        });
        
        document.getElementById("reset").addEventListener("click", function() {
            svg.transition().call(zoom.transform, d3.zoomIdentity);
        });
        
        let physicsEnabled = true;
        document.getElementById("toggle-physics").addEventListener("click", function() {
            if (physicsEnabled) {
                simulation.stop();
                this.textContent = "Resume Physics";
            } else {
                simulation.restart();
                this.textContent = "Pause Physics";
            }
            physicsEnabled = !physicsEnabled;
        });
        
        document.getElementById("export-png").addEventListener("click", function() {
            // Create a new canvas
            const canvas = document.createElement("canvas");
            const context = canvas.getContext("2d");
            
            // Set the canvas dimensions
            canvas.width = width;
            canvas.height = height;
            
            // Draw the SVG on the canvas
            const svgData = new XMLSerializer().serializeToString(svg.node());
            const img = new Image();
            
            img.onload = function() {
                context.drawImage(img, 0, 0);
                
                // Create a download link
                const a = document.createElement("a");
                a.download = "shadowscrawl_graph_" + Date.now() + ".png";
                a.href = canvas.toDataURL("image/png");
                a.click();
            };
            
            img.src = "data:image/svg+xml;base64," + btoa(unescape(encodeURIComponent(svgData)));
        });
        
        // Drag functionality
        function drag(simulation) {
            function dragstarted(event) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                event.subject.fx = event.subject.x;
                event.subject.fy = event.subject.y;
            }
            
            function dragged(event) {
                event.subject.fx = event.x;
                event.subject.fy = event.y;
            }
            
            function dragended(event) {
                if (!event.active) simulation.alphaTarget(0);
                event.subject.fx = null;
                event.subject.fy = null;
            }
            
            return d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended);
        }
        
        // Resize handler
        window.addEventListener("resize", function() {
            const width = window.innerWidth;
            const height = window.innerHeight;
            
            svg.attr("width", width)
               .attr("height", height)
               .attr("viewBox", [0, 0, width, height]);
               
            simulation.force("center", d3.forceCenter(width / 2, height / 2));
            simulation.restart();
        });
    </script>
</body>
</html>
"""
    
    def convert_linktree_to_graph(self, link_tree: LinkTree) -> Dict[str, Any]:
        """
        Convert a LinkTree object to a graph format suitable for visualization.
        
        Args:
            link_tree (LinkTree): The LinkTree object
            
        Returns:
            Dict[str, Any]: Graph data with nodes and links
        """
        nodes = []
        links = []
        node_ids = set()  # To track nodes that have been added
        
        # Get root URL
        root_url = link_tree.url
        
        # Process the tree using BFS
        queue = [(None, root_url)]  # (parent_url, current_url)
        while queue:
            parent_url, current_url = queue.pop(0)
            
            # Skip if already processed
            if current_url in node_ids:
                # If parent exists, add a link
                if parent_url and parent_url in node_ids:
                    links.append({
                        "source": parent_url,
                        "target": current_url
                    })
                continue
            
            # Mark as processed
            node_ids.add(current_url)
            
            # Get node data
            node_data = link_tree.get_link_data(current_url)
            is_root = (current_url == root_url)
            
            # Create node
            node = {
                "id": current_url,
                "name": node_data.get('title', 'Unknown'),
                "status": node_data.get('status', 'unknown'),
                "internal": node_data.get('internal', True),
                "root": is_root,
                "linkCount": len(node_data.get('links', []))
            }
            nodes.append(node)
            
            # Add link from parent if it exists
            if parent_url and parent_url in node_ids:
                links.append({
                    "source": parent_url,
                    "target": current_url
                })
            
            # Add child URLs to the queue
            child_links = node_data.get('links', [])
            for child_url in child_links:
                queue.append((current_url, child_url))
        
        return {
            "nodes": nodes,
            "links": links
        }
    
    def create_visualization(self, link_tree: LinkTree, open_browser: bool = True) -> str:
        """
        Create an interactive graph visualization from the LinkTree.
        
        Args:
            link_tree (LinkTree): The LinkTree to visualize
            open_browser (bool, optional): Whether to open the visualization in a browser. Defaults to True.
            
        Returns:
            str: Path to the saved HTML file
        """
        try:
            # Convert LinkTree to graph data
            graph_data = self.convert_linktree_to_graph(link_tree)
            
            # Generate HTML file with the graph data
            html_content = self.html_template.replace('GRAPH_DATA_PLACEHOLDER', json.dumps(graph_data))
            
            # Create filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            safe_url = "".join(c if c.isalnum() else "_" for c in link_tree.url[:30])
            filename = f"shadowscrawl_viz_{safe_url}_{timestamp}.html"
            filepath = os.path.join(self.output_dir, filename)
            
            # Write HTML to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"Graph visualization saved to {filepath}")
            print(color(f"Graph visualization saved to {filepath}", "green"))
            
            # Open in browser if requested
            if open_browser:
                webbrowser.open(f"file://{os.path.abspath(filepath)}")
                self.logger.info("Opened visualization in browser")
            
            return filepath
            
        except Exception as e:
            self.logger.error(f"Error creating visualization: {str(e)}")
            print(color(f"Error creating visualization: {str(e)}", "red"))
            return ""


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # This would typically be called from main.py
    # visualizer = GraphVisualizer()
    # visualizer.create_visualization(link_tree)
