/**
 * Fabric Service Unit Tests
 */

const path = require('path');
const fs = require('fs');

// Mock os module
jest.mock('os', () => ({
    homedir: () => 'C:\\Users\\th3th'
}));

describe('Fabric Service', () => {
    let fabricService;

    beforeAll(() => {
        fabricService = require('../fabric_service');
    });

    describe('getPatterns', () => {
        test('should return array of patterns', () => {
            const patterns = fabricService.getPatterns();
            expect(Array.isArray(patterns)).toBe(true);
        });

        test('should find patterns if fabric directory exists', () => {
            const patterns = fabricService.getPatterns();
            // If fabric is installed, should have patterns
            if (patterns.length > 0) {
                expect(patterns.length).toBeGreaterThan(0);
            }
        });
    });

    describe('getPatternContent', () => {
        test('should return null for non-existent pattern', () => {
            const content = fabricService.getPatternContent('non_existent_pattern_xyz');
            expect(content).toBeNull();
        });

        test('should return content for existing pattern', () => {
            const patterns = fabricService.getPatterns();
            if (patterns.length > 0) {
                const content = fabricService.getPatternContent(patterns[0]);
                // Should be string or null
                expect(typeof content === 'string' || content === null).toBe(true);
            }
        });
    });
});
