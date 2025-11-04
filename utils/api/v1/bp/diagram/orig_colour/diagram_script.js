// Light mode state
let isLightMode = false;

// Toggle light mode function
function toggleLightMode() {
    isLightMode = !isLightMode;
    document.body.classList.toggle('light-mode', isLightMode);

    // Regenerate chart with new theme
    if (currentData) {
        createCoxcombChart(currentData.categories);
    }
}

// This function will be added to your main script block
function createSampleButtons() {
    const container = document.getElementById('sampleButtonsContainer');

    // Get the keys (e.g., 'adoption', 'best_practices') from the samples object
    const sampleKeys = Object.keys(samples);

    sampleKeys.forEach(key => {
        // Create a new button element
        const button = document.createElement('button');

        // Set the onclick event to call loadSample with the current key
        button.setAttribute('onclick', `loadSample('${key}')`);

        // Set the text content of the button using the title from the sample data
        button.textContent = key || `${key} Sample`;

        // Add a CSS class for styling
        button.classList.add('sample-button');

        // Append the button to the container
        container.appendChild(button);
    });
}

function loadfirstSample() {

    const sampleKeys = Object.keys(samples);

    loadSample(sampleKeys[0]);
}

// Global variables
let currentChart = null;
let currentData = null;
let adoptedText = null;
let notAdoptedText = null;

function loadSample(type) {
    document.getElementById('jsonInput').value = JSON.stringify(samples[type], null, 2);
    generateChart();
}

function validateData(data) {
    if (!data.categories || !Array.isArray(data.categories)) {
        throw new Error('JSON must contain a "categories" array');
    }
    if (data.categories.length === 0) {
        throw new Error('Categories array cannot be empty');
    }

    data.categories.forEach((cat, index) => {
        if (!cat.name) throw new Error(`Category ${index + 1} missing "name"`);
        if (typeof cat.value !== 'number') throw new Error(`Category "${cat.name}" missing numeric "value"`);
        if (!cat.shortName) cat.shortName = cat.name; // Default shortName to name
        if (!cat.group) cat.group = cat.name; // Default group to name
    });
}

function generateChart() {
    const errorDiv = document.getElementById('error');
    errorDiv.textContent = '';

    try {
        const jsonText = document.getElementById('jsonInput').value;
        if (!jsonText.trim()) throw new Error('Please enter JSON data');

        const data = JSON.parse(jsonText);
        validateData(data);

        // Update chart title
        document.getElementById('chartTitle').textContent = data.title || 'Chart';

        const includesBestPractice = typeof data.title === 'string' && data.title.includes("Best Practices");
        const includesVisibility = typeof data.title === 'string' && data.title.includes("Visibility");

        if (includesBestPractice) {
            adoptedText = 'in BP Mode';
            notAdoptedText = 'Not in BP Mode';
        } else if (includesVisibility) {
            adoptedText = 'Visible';
            notAdoptedText = 'Not Visible';
        } else {
            adoptedText = 'Adopted';
            notAdoptedText = 'Not Adopted';
        }


        // Store current data
        currentData = data;

        // Create the chart
        createCoxcombChart(data.categories);

    } catch (error) {
        errorDiv.textContent = `Error: ${error.message}`;
    }
}

function resetChart() {
    // Clear the chart
    d3.select('#chart').selectAll('*').remove();
    currentChart = null;
    currentData = null;
    document.getElementById('chartTitle').textContent = 'Overall Adoption';
    document.getElementById('jsonInput').value = '';
    document.getElementById('error').textContent = '';
}

// Helper function to estimate text width (approximate)
function estimateTextWidth(text, fontSize) {
    // Approximate character width based on font size for Lato font
    const avgCharWidth = fontSize * 0.6;

    // Get the actual length
    const actualLength = text.length;
    const compensatedLength = actualLength;

    return compensatedLength * avgCharWidth;
}


function createCoxcombChart(data) {
    // Clear existing chart
    d3.select('#chart').selectAll('*').remove();

    // Create grouped data for outer labels
    const groupedData = d3.group(data, d => d.group);
    const groups = Array.from(groupedData.keys());

    // Calculate group positions and spans
    const groupInfo = [];
    let currentIndex = 0;

    groups.forEach(groupName => {
        const groupItems = groupedData.get(groupName);
        const startIndex = currentIndex;
        const endIndex = currentIndex + groupItems.length - 1;

        groupInfo.push({
            name: groupName,
            items: groupItems,
            startIndex: startIndex,
            endIndex: endIndex,
            itemCount: groupItems.length
        });

        currentIndex += groupItems.length;
    });

    // Chart dimensions and setup
    const LabelGapToCircle = 37;
    const width = 760;
    const height = 760;
    const margin = 160;
    const innerRadius = 80;
    const centerOverlayRadius = innerRadius - 5;
    const labelRadius = Math.min(width, height) / 2 - margin;
    const maxRadius = labelRadius;
    const externalLabelRadius = labelRadius + LabelGapToCircle;

    let BottomGapCategoryPercentage = 15;

    // Theme-based colors
    const backgroundColor = isLightMode ? '#ffffff' : '#0a0a0a';
    const centerOverlayColor = isLightMode ? '#ffffff' : '#1a1a1a';
    const groupLabelBgColor = isLightMode ? '#f5f5f5' : '#0D0D0D';
    const groupLabelBorderColor = isLightMode ? '#bbb' : '#575757';
    const groupLabelTextColor = isLightMode ? '#333' : '#eeeeee';
    const radialLineColor = isLightMode ? '#FFFFFF' : '#000000';
    const separatorColor = isLightMode ? '#FFFFFF' : '#000';
    const externalLabelTextColor = isLightMode ? '#333' : '#ffffff';
    const centerDividerColor = isLightMode ? '#d0d0d0' : '#354252';



    const redPercentagUsedColor = '#E20019';
    const redLabelUsedColor = '#F8B1B1';
    const redBackgroundColor = '#F8C4C8';    //'#FAD0D2'

    const orangePercentagUsedColor = '#EB540D';
    const orangeLabelUsedColor = '#F5B181';
    const orangeBackgroundColor = '#FADAC3';

    const yellowPercentagUsedColor = '#F7A633';
    const yellowLabelUsedColor = '#FEE5BB';
    const yellowBackgroundColor = '#FCEDD0';

    const greenPercentagUsedColor = '#24A385'; //25B197
    const greenLabelUsedColor = '#92DDCD';
    const greenBackgroundColor = '#CBECE5';



    const ArcPadAngle = '0.01' // gap between diagram Segments


    //curved grouplabeling
    const groupLabelGroupsFontSize = '9.5px'; //11
    const groupLabelGroupsFontWeight = '300';
// Define a small padding angle for the group label arc
    const GROUP_PADDING_ANGLE = 0.0075; // Adjust this value (e.g., 0.005 radians)


    //outside labeling around the diagramm
    const LabelcontainerCategoryFontSize = '9'; //10
    const LabelcontainerCategoryFontWeight = '400'; //400

    const LabelcontainerPercentageFontSize = '18'; //20
    const LabelcontainerPercentageFontWeight = '300'; //300

    const LabelcontainerAdoptedFontSize = '8'; //10
    const LabelcontainerAdoptedFontWeight = '500'; //300


    //color full labeling 12 o-clock
    const GridLabelGroupsFontSize = '10px'; //12
    const GridLabelGroupsFontWeight = '400';


    //inner circle
    const CenterGroupAverageFontSize = '10'; //12
    const CenterGroupAverageFontWeight = '500'; //700

    const CenterGroupAveragePercentageFontSize = '36';
    const CenterGroupAveragePercentageFontWeight = '300';

    const CenterGroupAdoptedFontSize = '9.25';
    const CenterGroupAdoptedFontWeight = '300';
    /////////
    const CenterGroupNotAdaptedPercentageFontSize = '17';
    const CenterGroupNotAdaptedPercentageFontWeight = '300';

    const CenterGroupNotAdaptedFontSize = '10'; //10
    const CenterGroupNotAdaptedFontWeight = '300'; //400


    const ColorCircleLineWidth = "1.0";
    const ColorCircleLineOpacity = "0.75";


    const groupLabelOuterRadius = 25;

    // Consistent gap between percentage and "Adopted" text (5 pixels)
    const CONSISTENT_GAP = 10;


    // Grid label colors
    const gridLabelColors = {
        25: {stroke: redPercentagUsedColor, fill: redLabelUsedColor},
        50: {stroke: orangePercentagUsedColor, fill: orangeLabelUsedColor},
        75: {stroke: yellowPercentagUsedColor, fill: yellowLabelUsedColor},
        100: {stroke: greenPercentagUsedColor, fill: greenLabelUsedColor}
    };

    // Improved color functions based on percentage ranges matching circle border colors
    const getColor = (value) => {
        if (value >= 0 && value <= 25) return redPercentagUsedColor;    // Red - matches 25% circle border
        if (value > 25 && value <= 50) return orangePercentagUsedColor;    // Orange - matches 50% circle border
        if (value > 50 && value <= 75) return yellowPercentagUsedColor;    // Yellow - matches 75% circle border
        if (value > 75 && value <= 100) return greenPercentagUsedColor;   // Teal - matches 100% circle border
        return redPercentagUsedColor; // Default to red for any edge cases
    };

    // Updated percentage color function for outer labels
    const getColor_background = (value) => {
        if (value >= 0 && value <= 25) return redBackgroundColor;    // Red - matches 25% circle border
        if (value > 25 && value <= 50) return orangeBackgroundColor;    // Orange - matches 50% circle border
        if (value > 50 && value <= 75) return yellowBackgroundColor;    // Yellow - matches 75% circle border
        if (value > 75 && value <= 100) return greenBackgroundColor;   // Teal - matches 100% circle border
        return redBackgroundColor; // Default to red for any edge cases
    };

    // Updated percentage color function for outer labels
    const getPercentageColor = (value) => {
        if (value >= 0 && value <= 25) return redPercentagUsedColor;    // Red - matches 25% circle border
        if (value > 25 && value <= 50) return orangePercentagUsedColor;    // Orange - matches 50% circle border
        if (value > 50 && value <= 75) return yellowPercentagUsedColor;    // Yellow - matches 75% circle border
        if (value > 75 && value <= 100) return greenPercentagUsedColor;   // Teal - matches 100% circle border
        return redPercentagUsedColor; // Default to red for any edge cases
    };


    // Create SVG
    const svg = d3.select('#chart')
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    const defs = svg.append('defs');
    const g = svg.append('g')
        .attr('transform', `translate(${width / 2}, ${height / 2})`);

    // Scales
    const angleScale = d3.scaleBand()
        .domain(data.map(d => d.name))
        .range([0, 2 * Math.PI])
    //.range([-Math.PI / 2, 2 * Math.PI - Math.PI / 2])
    //.paddingInner(0.04); // Reduced from 0.02 to make separators thinner

    const radiusScale = d3.scaleLinear()
        .domain([0, 100])
        .range([innerRadius, maxRadius]);

    // Arc generators
    const arc = d3.arc()
        .innerRadius(innerRadius)
        .outerRadius(d => radiusScale(d.value))
        .startAngle(d => angleScale(d.name))
        .endAngle(d => angleScale(d.name) + angleScale.bandwidth())
        .padAngle(ArcPadAngle); // Reduced from 0.01 to make separators thinner

    // background Arc generators
    const backgroundArc = d3.arc()
        .innerRadius(innerRadius)
        .outerRadius(maxRadius) // Uses maxRadius for full size
        .startAngle(d => angleScale(d.name))
        .endAngle(d => angleScale(d.name) + angleScale.bandwidth())
        .padAngle(ArcPadAngle);

    // Tooltip
    const tooltip = d3.select('#tooltip');


    // Create segments
    const segments = g.selectAll('.segment')
        .data(data)
        .enter()
        .append('g')
        .attr('class', 'segment');


    //segments BACKGROUND
    segments.append('path')
        .attr('d', backgroundArc)
        .style('fill', d => getColor_background(d.value))
        .style('stroke', 'none');

    //segments values
    segments.append('path')
        .attr('d', arc)
        .style('fill', d => getColor(d.value))
        .style('stroke', separatorColor)
        .style('stroke-width', 0.5) // Reduced from 1 to make separators thinner
        .style('opacity', 0.9)
        .style('cursor', 'pointer')
        .on('mouseover', function (event, d) {
            d3.select(this).style('opacity', 1).style('filter', 'brightness(1.1)');
            tooltip.style('opacity', 1)
                .html(`<strong>${d.name}</strong><br/>
                               <span style="color: ${getPercentageColor(d.value)};">${d.value}% Adopted</span><br/>
                               <span style="color: ${isLightMode ? '#666' : '#888'};">Click for details</span>`)
                .style('left', (event.pageX + 15) + 'px')
                .style('top', (event.pageY - 15) + 'px');
        })
        .on('mouseout', function () {
            d3.select(this).style('opacity', 0.9).style('filter', 'none');
            tooltip.style('opacity', 0);
        })
        .on('click', function (event, d) {
            alert(`${d.name}: ${d.value}% adoption rate`);
        });


    // Create grouped curved labels with improved text orientation
    const groupLabelGroups = g.selectAll('.group-label-group')
        .data(groupInfo)
        .enter()
        .append('g')
        .attr('class', 'group-label-group');



    groupLabelGroups.each(function (groupData, i) {
        const group = d3.select(this);
        const pathId = `group-label-path-${i}`;

        const firstItem = groupData.items[0];
        const lastItem = groupData.items[groupData.items.length - 1];

        // CALCULATE START AND END ANGLE FOR THE GROUP ARC:
        // Apply the padding angle to pull the group arc inwards from the segment boundary
        const startAngle = angleScale(firstItem.name) + GROUP_PADDING_ANGLE;
        const endAngle = (angleScale(lastItem.name) + angleScale.bandwidth()) - GROUP_PADDING_ANGLE;

        // Calculate middle angle for text orientation decision
        const middleAngle = (startAngle + endAngle) / 2;
        const normalizedAngle = middleAngle % (2 * Math.PI);

        // Determine if text should be flipped (upside down prevention)
        const shouldFlip = normalizedAngle > Math.PI / 2 && normalizedAngle < 3 * Math.PI / 2;


        const pathRadius = labelRadius + groupLabelOuterRadius / 2 + 2;

        let pathData;

        if (shouldFlip) {
            // Reverse the path direction for upside-down text
            pathData = d3.arc()
                .innerRadius(pathRadius + 5)
                .outerRadius(pathRadius + 3)
                .startAngle(endAngle)
                .endAngle(startAngle)();
        } else {
            pathData = d3.arc()
                .innerRadius(pathRadius)
                .outerRadius(pathRadius)
                .startAngle(startAngle)
                .endAngle(endAngle)();
        }

        defs.append('path')
            .attr('id', pathId)
            .attr('d', pathData);

        const groupLabelArc = d3.arc()
            .innerRadius(labelRadius)
            .outerRadius(labelRadius + groupLabelOuterRadius)
            .startAngle(startAngle)
            .endAngle(endAngle);

        group.append('path')
            .attr('d', groupLabelArc())
            .style('fill', groupLabelBgColor)
            .style('stroke', groupLabelBorderColor)
            .style('stroke-width', 1);

        const textElement = group.append('text')
            .attr('dy', shouldFlip ? '-5px' : '0.75%')
            .style('text-anchor', 'middle')
            .style('line-height', '10px');

        textElement.append('textPath')
            .attr('xlink:href', `#${pathId}`)
            .attr('startOffset', '25%')
            .style('fill', groupLabelTextColor)
            .style('stroke', 'transparent')
            .style('font-family', 'Lato, sans-serif')
            .style('font-size', groupLabelGroupsFontSize) // Reduced from 12px
            .style('font-weight', groupLabelGroupsFontWeight) // Reduced from 400 to make less bold
            .text(groupData.name);
    });


    // Create grid circles with reduced thickness
    const gridValues = [25, 50, 75, 100];
    g.selectAll('.grid-circle')
        .data(gridValues)
        .enter()
        .append('circle')
        .attr('class', 'grid-line')
        .attr('r', d => radiusScale(d))
        .style('fill', 'none')
        .style('stroke', d => gridLabelColors[d].stroke)
        .style('stroke-width', ColorCircleLineWidth) // Reduced from 2 to make circles thinner
        .style('opacity', ColorCircleLineOpacity); // Reduced from 0.8 to make circles more subtle

    // Add radial lines
    segments.append('line')
        .attr('x1', 0)
        .attr('y1', 0)
        .attr('x2', d => {
            const angle = angleScale(d.name);
            return Math.sin(angle) * maxRadius;
        })
        .attr('y2', d => {
            const angle = angleScale(d.name);
            return -Math.cos(angle) * maxRadius;
        })
        .style('stroke', radialLineColor)
        .style('stroke-width', 3)
        .style('opacity', 1);


    // Create external labels with consistent spacing
    const externalLabelGroups = g.selectAll('.external-label-group')
        .data(data)
        .enter()
        .append('g')
        .attr('class', 'external-label-group');

    externalLabelGroups.each(function (d, i) {
        const group = d3.select(this);
        const angle = angleScale(d.name) + angleScale.bandwidth() / 2;
        const x = Math.sin(angle) * externalLabelRadius;
        const y = -Math.cos(angle) * externalLabelRadius;

        // Determine position relative to circle (left, right, top, bottom)
        const isLeft = x < -50;
        const isRight = x > 50;
        const isTop = y < -50;
        const isBottom = y > 50;

        // Calculate text widths for intelligent positioning
        categoryWidth = estimateTextWidth(d.shortName, LabelcontainerCategoryFontSize);
        percentageText = d.value + '%';
        percentageWidth = estimateTextWidth(percentageText, LabelcontainerPercentageFontSize);
        adoptedWidth = estimateTextWidth(adoptedText, LabelcontainerAdoptedFontSize);
        gapWidth = estimateTextWidth("--", LabelcontainerAdoptedFontSize);



        const labelContainer = group.append('g')
            .attr('transform', `translate(${x}, ${y})`);

        // Smart positioning calculations with consistent spacing
        let categoryX = 0, categoryAnchor = 'middle', categoryY = -15;
        let percentageX = 0, percentageAnchor = 'middle', percentageY = 4;
        let adoptedX = 0, adoptedAnchor = 'middle', adoptedY = 3;



        if (isLeft) {
            // Left side: align to right edge of category name
            categoryAnchor = 'end';
            categoryX = 0;

            // Position "Adopted" at right edge, percentage with consistent gap to the left
            adoptedAnchor = 'end';
            adoptedX = 0;
            gapX = - adoptedWidth;

            percentageAnchor = 'end';
            percentageX =  - adoptedWidth - 3;

            if (isBottom)
            {
                categoryY = categoryY + BottomGapCategoryPercentage;
                percentageY = percentageY + BottomGapCategoryPercentage;
                adoptedY = adoptedY + BottomGapCategoryPercentage;
            }
        } else if (isRight) {
            // Right side: align to left edge of category name
            categoryAnchor = 'start';
            categoryX = 0;

            // Position percentage at left edge, "Adopted" with consistent gap to the right
            percentageAnchor = 'start';
            percentageX = 0;

            gapX = percentageWidth;

            adoptedAnchor = 'start';
            //adoptedX = percentageWidth + CONSISTENT_GAP;
            adoptedX = percentageWidth + gapWidth;

            if (isBottom)
            {
                categoryY = categoryY + BottomGapCategoryPercentage;
                percentageY = percentageY + BottomGapCategoryPercentage;
                adoptedY = adoptedY + BottomGapCategoryPercentage;
            }
        } else {
            // Top/Bottom: center alignment with consistent spacing
            categoryAnchor = 'middle';
            categoryX = 0;

            // Center the percentage + adopted combination with consistent gap
            const totalWidth = percentageWidth + CONSISTENT_GAP + adoptedWidth;
            percentageAnchor = 'start';
            percentageX = -totalWidth / 2;

            adoptedAnchor = 'start';
            adoptedX = -totalWidth / 2 + percentageWidth + CONSISTENT_GAP;

            gapX = -totalWidth / 2 + percentageWidth;

            if (isBottom)
            {
                categoryY = categoryY + BottomGapCategoryPercentage;
                percentageY = percentageY + BottomGapCategoryPercentage;
                adoptedY = adoptedY + BottomGapCategoryPercentage;
            }
        }


        // Category name with smart positioning
        labelContainer.append('text')
            .attr('x', categoryX)
            .attr('y', categoryY)
            .style('text-anchor', categoryAnchor)
            .style('font-family', 'Lato, sans-serif')
            .style('font-size', LabelcontainerCategoryFontSize+"px")
            .style('font-weight', LabelcontainerCategoryFontWeight)
            .style('fill', externalLabelTextColor)
            .text(d.shortName);

        // Percentage with calculated positioning
        labelContainer.append('text')
            .attr('x', percentageX)
            .attr('y', percentageY)
            .style('text-anchor', percentageAnchor)
            .style('font-family', 'Lato, sans-serif')
            .style('font-size', LabelcontainerPercentageFontSize+"px")
            .style('font-weight', LabelcontainerPercentageFontWeight)
            .style('fill', getPercentageColor(d.value))
            .text(percentageText);

        // "Adopted" text with calculated positioning
        labelContainer.append('text')
            .attr('x', adoptedX)
            .attr('y', adoptedY)
            .style('text-anchor', adoptedAnchor)
            .style('font-family', 'Lato, sans-serif')
            .style('font-size', LabelcontainerAdoptedFontSize+"px")
            .style('font-weight', LabelcontainerAdoptedFontWeight)
            .style('fill', externalLabelTextColor)
            .text(adoptedText);

        // "gap" text with calculated positioning
        //labelContainer.append('text')
        //    .attr('x', gapX)
        //    .attr('y', adoptedY)
        //    .style('text-anchor', adoptedAnchor)
        //    .style('font-family', 'Lato, sans-serif')
        //    .style('font-size', LabelcontainerAdoptedFontSize+"px")
        //    .style('font-weight', LabelcontainerAdoptedFontWeight)
        //    .style('fill', externalLabelTextColor)
        //    .text("--");
    });

    // Add center overlay circle
    g.append('circle')
        .attr('r', centerOverlayRadius)
        .style('fill', centerOverlayColor)
        .style('stroke', 'none');

    // Calculate averages for center
    const totalValue = data.reduce((sum, d) => sum + d.value, 0);
    const average = Math.round(totalValue / data.length);
    const notAdoptedpercentage = 100 - average;

    // Center content with consistent spacing
    const centerGroup = g.append('g').attr('class', 'center-content');
    const CENTER_GAP = 5; // Consistent gap for center labels too

    centerGroup.append('text')
        .attr('y', -45)
        .attr('text-anchor', 'middle')
        .style('font-family', 'Lato, sans-serif')
        .style('font-size', CenterGroupAverageFontSize+"px")
        .style('font-weight', CenterGroupAverageFontWeight)
        .style('fill', externalLabelTextColor)
        .text('Average');

    // Main percentage with consistent "Adopted" positioning
    const averagePercentageText = average + '%';
    const averagePercentageWidth = estimateTextWidth(averagePercentageText, 40);

    centerGroup.append('text')
        .attr('y', -5)
        .attr('text-anchor', 'middle')
        .style('font-family', 'Lato, sans-serif')
        .style('font-size', CenterGroupAveragePercentageFontSize+"px")
        .style('font-weight', CenterGroupAveragePercentageFontWeight)
        .style('fill', getPercentageColor(average))
        .text(averagePercentageText);

    centerGroup.append('text')
        .attr('x', centerOverlayRadius / 2 - 40)
        .attr('y', 10)
        .attr('text-anchor', 'middle')
        .style('font-family', 'Lato, sans-serif')
        .style('font-size', CenterGroupAdoptedFontSize+"px")
        .style('font-weight', CenterGroupAdoptedFontWeight)
        .style('fill', externalLabelTextColor)
        .text(adoptedText);

    centerGroup.append('rect')
        .attr('width', 100)
        .attr('height', 1)
        .attr('fill', centerDividerColor)
        .attr('y', 18)
        .attr('x', -50);

    // "Not Adopted" percentage with consistent positioning
    const notAdoptedPercentageText = notAdoptedpercentage + '%';
    const notAdoptedPercentageWidth = estimateTextWidth(notAdoptedPercentageText, CenterGroupNotAdaptedPercentageFontSize);
    const notAdoptedWidth = estimateTextWidth(notAdoptedText, CenterGroupNotAdaptedFontSize);

    // Center the percentage + adopted combination with consistent gap
    const totalNotAdaptedWidth = notAdoptedPercentageWidth + gapWidth + notAdoptedWidth;
    CenterGroupNotAdaptedPercentageX = 5 -totalNotAdaptedWidth / 2;
    CenterGroupNotAdaptedX = 5 -totalNotAdaptedWidth / 2 + notAdoptedPercentageWidth + gapWidth;
    CenterGroupNotAdaptedGapX = 5 -totalNotAdaptedWidth / 2 + notAdoptedPercentageWidth;


    centerGroup.append('text')
        .attr('y', 40)
        .attr('x', CenterGroupNotAdaptedPercentageX)
        .attr('text-anchor', 'left')
        .style('font-family', 'Lato, sans-serif')
        .style('font-size', CenterGroupNotAdaptedPercentageFontSize+"px")
        .style('font-weight', CenterGroupNotAdaptedPercentageFontWeight)
        //.style('fill', getPercentageColor(notAdopted))
        .style('fill', externalLabelTextColor)
        .text(notAdoptedPercentageText);

    centerGroup.append('text')
        //.attr('x', centerOverlayRadius / 2 - 38)
        //.attr('y', centerOverlayRadius / 2 + 16)
        .attr('y', 40)
        .attr('x', CenterGroupNotAdaptedX)
        .attr('text-anchor', 'left')
        .style('font-family', 'Lato, sans-serif')
        .style('font-size', CenterGroupNotAdaptedFontSize+"px")
        .style('font-weight', CenterGroupNotAdaptedFontWeight)
        .style('fill', externalLabelTextColor)
        .text(notAdoptedText);

    //centerGroup.append('text')
        //.attr('x', centerOverlayRadius / 2 - 38)
        //.attr('y', centerOverlayRadius / 2 + 16)
    //    .attr('y', 40)
    //    .attr('x', CenterGroupNotAdaptedGapX)
    //    .attr('text-anchor', 'left')
    //    .style('font-family', 'Lato, sans-serif')
    //    .style('font-size', CenterGroupNotAdaptedFontSize+"px")
    //    .style('font-weight', CenterGroupNotAdaptedFontWeight)
    //    .style('fill', externalLabelTextColor)
    //    .text("--");

    // Create grid labels
    const gridLabelGroups = g.selectAll('.grid-label-group')
        .data(gridValues)
        .enter()
        .append('g')
        .attr('class', 'grid-label-group')
        .attr('transform', d => `translate(0, ${-radiusScale(d)})`);

    gridLabelGroups.append('rect')
        .attr('width', 44)
        .attr('height', 15)
        .attr('rx', 10)
        .attr('x', -22)
        .attr('y', -8)
        .style('stroke', d => gridLabelColors[d].stroke)
        .style('stroke-width', 0.5)
        .style('fill', d => gridLabelColors[d].fill)
        .style('opacity', 1)
        .style('pointer-events', 'none')
        .style('filter', 'drop-shadow(0px 2px 2px rgba(0, 0, 0, 0.24))');

    gridLabelGroups.append('text')
        .attr('y', 0)
        .attr('dy', '0.3em')
        .attr('text-anchor', 'middle')
        .style('font-family', 'Lato, sans-serif')
        .style('font-size', GridLabelGroupsFontSize)
        .style('font-weight', GridLabelGroupsFontWeight)
        .style('fill', '#000000') //changed
        .style('pointer-events', 'none')
        .text(d => d + '%');

    // Add animations
    segments.selectAll('path')
        .style('opacity', 0)
        .transition()
        .duration(1000)
        .delay((d, i) => i * 50)
        .style('opacity', 0.9);

    groupLabelGroups.selectAll('text')
        .style('opacity', 0)
        .transition()
        .duration(800)
        .delay((d, i) => i * 50 + 500)
        .style('opacity', 1);

    externalLabelGroups.selectAll('text')
        .style('opacity', 0)
        .transition()
        .duration(800)
        .delay((d, i) => i * 50 + 700)
        .style('opacity', 1);

    gridLabelGroups
        .style('opacity', 0)
        .transition()
        .duration(600)
        .delay(300)
        .style('opacity', 1);

    centerGroup.selectAll('text, rect')
        .style('opacity', 0)
        .transition()
        .duration(800)
        .delay(400)
        .style('opacity', 1);

    // Store current chart reference
    currentChart = {svg, g, data};
}

// New function to capture chart as Base64 data
function captureChartAsBase64() {
    return new Promise((resolve, reject) => {
        const chartContainer = document.querySelector('.chart-container');
        if (!chartContainer) {
            reject('Chart container not found.');
            return;
        }
        const backgroundColor = isLightMode ? '#ffffff' : '#0a0a0a';
        html2canvas(chartContainer, {
            allowTaint: true,
            useCORS: true,
            backgroundColor: backgroundColor,
            scale: 2
        }).then(canvas => {
            const dataUrl = canvas.toDataURL('image/jpeg', 1.0);
            resolve(dataUrl);
        }).catch(error => reject(error));
    });
}

// New function to generate all charts and store Base64 data in a global array
async function generateAllJpgsAndStoreData() {
    // Clear any previous data
    window.allChartsData = [];
    const sampleKeys = Object.keys(samples);
    for (const key of sampleKeys) {
        console.log(`Generating chart and capturing data for: ${key}`);
        loadSample(key);
        await delay(1500); // Wait for the chart to render fully
        try {
            const dataUrl = await captureChartAsBase64();
            window.allChartsData.push({
                name: `${key.replace(/\s/g, '-')}.jpg`,
                data: dataUrl
            });
            console.log(`Captured chart data for ${key}`);
        } catch (e) {
            console.error(`Failed to capture chart for ${key}:`, e);
        }
    }
    console.log('All charts have been processed.');
}

const delay = ms => new Promise(res => setTimeout(res, ms));

// Note: The previous saveChartAsJpg() is now replaced with a new version
// if you want to keep the single-file download functionality.
function saveChartAsJpg(jpgFileName) {
    const chartContainer = document.querySelector('.chart-container');
    if (!chartContainer) {
        console.error('Chart container not found.');
        return;
    }
    const backgroundColor = isLightMode ? '#ffffff' : '#0a0a0a';
    html2canvas(chartContainer, {
        allowTaint: true,
        useCORS: true,
        backgroundColor: backgroundColor,
        scale: 2
    }).then(canvas => {
        const jpgDataUrl = canvas.toDataURL('image/jpeg', 1.0);
        const link = document.createElement('a');
        link.href = jpgDataUrl;
        link.download = jpgFileName;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    });
};

// Old function signature for generateAllJpgs for compatibility.
// It now calls the new function internally.
function generateAllJpgs() {
    generateAllJpgsAndStoreData();
}

const generateAllJpgsManualClick = async () => {
    const sampleKeys = Object.keys(samples);
    for (const key of sampleKeys) {
        console.log(`Generating chart and saving JPG for: ${key}`);
        loadSample(key);
        // Delay to allow the chart to render fully before saving
        await delay(1500);
        saveChartAsJpg(`${key.replace(/\s/g, '-')}.jpg`);
    }
    console.log('All charts have been saved.');
};


// Load initial sample on page load
window.onload = () => {
    toggleLightMode();
    createSampleButtons();
    loadfirstSample();
}
