import React from 'react';
import WatermarkLogo from './WatermarkLogo';
import WatermarkText from './WatermarkText';
import Hider from '../layout/Hider';

interface WatermarkWrapperProps {
  className?: string;
}

const WatermarkWrapper: React.FC<WatermarkWrapperProps> = ({ className }) => (
  <div className={className}>
    <WatermarkLogo />
    <Hider hideOnMobile>
      <WatermarkText />
    </Hider>
  </div>
);

export default WatermarkWrapper;
