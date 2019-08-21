import * as React from 'react'
import * as Kb from '../common-adapters/mobile.native'
import * as Styles from '../styles'
import {
  serviceIdToIconFont,
  serviceIdToAccentColor,
  serviceIdToLongLabel,
  inactiveServiceAccentColor,
} from './shared'
import * as Constants from '../constants/team-building'
import {Props, IconProps} from './service-tab-bar'
import {memoize} from '../util/memoize'

const mapRange = (v: number, fromMin: number, fromMax: number, toMin: number, toMax: number) => {
  return ((v - fromMin) / (fromMax - fromMin)) * (toMax - toMin) + toMin
}

export const labelHeight = 34

const serviceMinWidthWhenSmall = (containerWidth: number) => {
  const minWidth = 70
  if (containerWidth <= minWidth) {
    return minWidth
  }
  const p = containerWidth / minWidth // count that would fit onscreen at ideal size
  let n = Math.floor(p) + 0.5
  if (p % 1 < 0.5) {
    n -= 1
  }
  // n = count that will fit onscreen at returned size
  return containerWidth / n
}

const ServiceIcon = (props: IconProps) => {
  const smallWidth = serviceMinWidthWhenSmall(Styles.dimensionWidth)
  const bigWidth = Math.max(smallWidth, 92)
  return (
    <Kb.ClickableBox onClick={props.onClick}>
      <Kb.Box2
        direction="vertical"
        centerChildren={true}
        style={Styles.collapseStyles([
          styles.serviceIconContainer,
          {width: mapRange(props.labelPresence, 0, 1, smallWidth, bigWidth)},
        ])}
      >
        <Kb.Icon
          fontSize={18}
          type={serviceIdToIconFont(props.service)}
          color={props.isActive ? serviceIdToAccentColor(props.service) : inactiveServiceAccentColor}
        />
        <Kb.Box2
          direction="vertical"
          style={{
            height: labelHeight * props.labelPresence,
            opacity: props.labelPresence,
            overflow: 'hidden',
          }}
        >
          <Kb.Box2 direction="vertical" style={{height: labelHeight, width: 74}}>
            <Kb.Text type="BodyTiny" center={true} lineClamp={2}>
              {props.label}
            </Kb.Text>
          </Kb.Box2>
        </Kb.Box2>
        {!!props.showCount && props.count === null && (
          <Kb.Icon
            type="icon-progress-grey-animated"
            color={Styles.globalColors.greyDark}
            style={styles.pendingIcon}
          />
        )}
        {!!props.showCount && props.count !== null && (
          <Kb.Text type="BodyTinySemibold">{props.count && props.count === 11 ? '10+' : props.count}</Kb.Text>
        )}
      </Kb.Box2>
      <Kb.Box2
        direction="horizontal"
        fullWidth={true}
        style={Styles.collapseStyles([
          props.isActive ? styles.activeTabBar : styles.inactiveTabBar,
          props.isActive && {backgroundColor: serviceIdToAccentColor(props.service)},
        ])}
      />
    </Kb.ClickableBox>
  )
}

const undefToNull = (n: number | undefined | null): number | null => (n === undefined ? null : n)

export const ServiceTabBar = (props: Props) => {
  const [showLabels, setShowLabels] = React.useState(props.initialShowLabels)
  const [locked, setLocked] = React.useState(false)
  const onClose = () => {
    setShowLabels(false)
    props.onLabelsSeen()
  }
  const deferClose = Kb.useTimeout(onClose, 2000)
  const deferUnlock = Kb.useTimeout(() => setLocked(false), 250)
  const onScroll = React.useCallback(() => {
    deferClose()
    if (locked) {
      // On android the animation of narrowing while hiding labels caused scroll events
      // which caused the labels to re-open. To work around that issue the state is 'locked'
      // for a trice after animation completes.
      return
    }
    setShowLabels(true)
  }, [deferClose, locked, setShowLabels])
  React.useEffect(deferClose, [])
  return (
    <Kb.Box2 direction="horizontal" fullWidth={true} style={styles.barPlaceholder}>
      <Kb.Animated
        onStart={() => setLocked(true)}
        onRest={deferUnlock}
        to={{presence: showLabels ? 1 : 0}}
        config={{clamp: true, tension: 400}}
      >
        {({presence}) => (
          <Kb.Box2
            direction="vertical"
            fullWidth={true}
            style={Styles.collapseStyles([
              styles.tabBarContainer,
              {height: 48 + labelHeight * presence, shadowOpacity: presence * 0.1},
            ])}
          >
            <Kb.ScrollView
              horizontal={true}
              showsHorizontalScrollIndicator={false}
              onScroll={onScroll}
              scrollEventThrottle={1000}
            >
              {Constants.services.map(service => (
                <ServiceIcon
                  key={service}
                  service={service}
                  label={serviceIdToLongLabel(service)}
                  labelPresence={presence}
                  onClick={() => props.onChangeService(service)}
                  count={undefToNull(props.serviceResultCount[service])}
                  showCount={props.showServiceResultCount}
                  isActive={props.selectedService === service}
                />
              ))}
            </Kb.ScrollView>
          </Kb.Box2>
        )}
      </Kb.Animated>
    </Kb.Box2>
  )
}

const styles = Styles.styleSheetCreate(() => ({
  activeTabBar: {
    backgroundColor: Styles.globalColors.blue,
    height: 2,
  },
  barPlaceholder: {
    height: 48,
    position: 'relative',
  },
  inactiveTabBar: {
    borderBottomWidth: 1,
    borderColor: Styles.globalColors.black_10,
    height: 2,
  },
  pendingIcon: {height: 17, width: 17},
  serviceIconContainer: {
    flex: 1,
    paddingBottom: Styles.globalMargins.tiny,
    paddingTop: Styles.globalMargins.tiny,
  },
  tabBarContainer: {
    backgroundColor: Styles.globalColors.white,
    position: 'absolute',
    shadowOffset: {height: 3, width: 0},
    shadowRadius: 2,
    top: 0,
  },
}))

export default ServiceTabBar